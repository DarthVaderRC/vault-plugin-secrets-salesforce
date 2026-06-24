package salesforce

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const jwtBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// tokenResult is the parsed outcome of a successful token request.
type tokenResult struct {
	AccessToken string
	InstanceURL string
	TokenType   string
	Scope       string
	ExpiresIn   int // seconds; 0 when Salesforce omits expires_in
}

// salesforceError represents an OAuth error returned by the token endpoint.
type salesforceError struct {
	StatusCode  int
	Code        string
	Description string
}

func (e *salesforceError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("salesforce token endpoint returned HTTP %d", e.StatusCode)
	}
	return fmt.Sprintf("salesforce oauth error %q: %s (HTTP %d)", e.Code, e.Description, e.StatusCode)
}

// httpClientFor builds an *http.Client honoring the config's TLS settings.
func httpClientFor(cfg *salesforceConfig) (*http.Client, error) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: cfg.TLSSkipVerify, //nolint:gosec // opt-in for sandbox/testing only
		MinVersion:         tls.VersionTLS12,
	}
	if cfg.CACert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.CACert)) {
			return nil, fmt.Errorf("failed to parse ca_cert PEM")
		}
		tlsConf.RootCAs = pool
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConf},
	}, nil
}

// requestClientCredentialsToken performs the client_credentials grant.
func requestClientCredentialsToken(ctx context.Context, cfg *salesforceConfig, role *salesforceRole) (*tokenResult, error) {
	// Salesforce's Client Credentials flow does NOT accept a "scope" request
	// parameter — sending one fails with `invalid_request: scope parameter not
	// supported`. The granted scopes are fixed by the Connected App's OAuth
	// configuration, so role.Scopes is intentionally not forwarded here.
	form := url.Values{
		"grant_type":    {grantClientCredential},
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
	}
	return doTokenRequest(ctx, cfg, form)
}

// requestJWTBearerToken performs the JWT Bearer grant: it signs an assertion
// with the config private key and exchanges it for an access token.
func requestJWTBearerToken(ctx context.Context, cfg *salesforceConfig, role *salesforceRole) (*tokenResult, error) {
	assertion, err := buildJWTAssertion(cfg, role, time.Now())
	if err != nil {
		return nil, err
	}
	form := url.Values{
		"grant_type": {jwtBearerGrantType},
		"assertion":  {assertion},
	}
	return doTokenRequest(ctx, cfg, form)
}

// doTokenRequest posts the form to the token endpoint and parses the result.
func doTokenRequest(ctx context.Context, cfg *salesforceConfig, form url.Values) (*tokenResult, error) {
	client, err := httpClientFor(cfg)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.tokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("reading token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, parseTokenError(resp.StatusCode, body)
	}

	var parsed struct {
		AccessToken string `json:"access_token"`
		InstanceURL string `json:"instance_url"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decoding token response: %w", err)
	}
	if parsed.AccessToken == "" {
		return nil, fmt.Errorf("token response contained no access_token")
	}

	return &tokenResult{
		AccessToken: parsed.AccessToken,
		InstanceURL: parsed.InstanceURL,
		TokenType:   parsed.TokenType,
		Scope:       parsed.Scope,
		ExpiresIn:   parsed.ExpiresIn,
	}, nil
}

// parseTokenError maps a non-200 token response to a salesforceError, surfacing
// the OAuth error/description while never echoing request secrets.
func parseTokenError(status int, body []byte) error {
	sfErr := &salesforceError{StatusCode: status}
	var parsed struct {
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil {
		sfErr.Code = parsed.Error
		sfErr.Description = parsed.ErrorDescription
	}
	return sfErr
}
