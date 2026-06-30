// Copyright (c) 2026 DarthVaderRC.
// SPDX-License-Identifier: MPL-2.0

package salesforce

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand"
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
func requestClientCredentialsToken(ctx context.Context, cfg *salesforceConfig, _ *salesforceRole) (*tokenResult, error) {
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

// revokeToken calls the Salesforce /revoke endpoint to invalidate an access
// token server-side. Salesforce returns HTTP 200 on success. The endpoint shares
// the (already host-validated) token endpoint base.
func revokeToken(ctx context.Context, cfg *salesforceConfig, accessToken string) error {
	if accessToken == "" {
		return nil
	}
	client, err := httpClientFor(cfg)
	if err != nil {
		return err
	}
	form := url.Values{"token": {accessToken}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.revokeURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("revoke request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("salesforce revoke returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// Retry policy for transient token-endpoint failures (network errors, HTTP 429,
// and 5xx). Declared as vars so tests can shrink the backoff.
var (
	tokenRetryMaxAttempts = 3
	tokenRetryBaseBackoff = 200 * time.Millisecond
)

// doTokenRequest posts the form to the token endpoint and parses the result,
// retrying transient failures (network errors, HTTP 429, and 5xx) with
// exponential backoff and jitter.
func doTokenRequest(ctx context.Context, cfg *salesforceConfig, form url.Values) (*tokenResult, error) {
	client, err := httpClientFor(cfg)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for attempt := 0; attempt < tokenRetryMaxAttempts; attempt++ {
		if attempt > 0 {
			backoff := tokenRetryBaseBackoff * time.Duration(1<<(attempt-1))
			backoff += time.Duration(rand.Int63n(int64(backoff)/2 + 1)) // jitter
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}

		res, retryable, err := doTokenRequestOnce(ctx, client, cfg, form)
		if err == nil {
			return res, nil
		}
		lastErr = err
		if !retryable {
			return nil, err
		}
	}
	return nil, lastErr
}

// doTokenRequestOnce performs a single token request. It returns retryable=true
// when the failure is transient (network error, HTTP 429, or 5xx).
func doTokenRequestOnce(ctx context.Context, client *http.Client, cfg *salesforceConfig, form url.Values) (*tokenResult, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.tokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		// Network/transport errors are transient; retry unless the context ended.
		if ctx.Err() != nil {
			return nil, false, fmt.Errorf("token request failed: %w", err)
		}
		return nil, true, fmt.Errorf("token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, true, fmt.Errorf("reading token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, isRetryableStatus(resp.StatusCode), parseTokenError(resp.StatusCode, body)
	}

	var parsed struct {
		AccessToken string `json:"access_token"`
		InstanceURL string `json:"instance_url"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, false, fmt.Errorf("decoding token response: %w", err)
	}
	if parsed.AccessToken == "" {
		return nil, false, fmt.Errorf("token response contained no access_token")
	}

	return &tokenResult{
		AccessToken: parsed.AccessToken,
		InstanceURL: parsed.InstanceURL,
		TokenType:   parsed.TokenType,
		Scope:       parsed.Scope,
		ExpiresIn:   parsed.ExpiresIn,
	}, false, nil
}

// isRetryableStatus reports whether an HTTP status warrants a retry: rate
// limiting (429) and transient server errors (5xx).
func isRetryableStatus(status int) bool {
	return status == http.StatusTooManyRequests || status >= 500
}

// isTransientMintError reports whether a token-mint failure is transient
// (network/transport error, HTTP 429, or 5xx) and therefore safe to ride out by
// serving a still-valid cached token. A definitive OAuth error (e.g.
// invalid_grant / invalid_client) is NOT transient: callers should purge the
// cached token and fail closed rather than keep serving it.
func isTransientMintError(err error) bool {
	var sfErr *salesforceError
	if errors.As(err, &sfErr) {
		return isRetryableStatus(sfErr.StatusCode)
	}
	// Network/transport, parse, or signing errors are treated as transient.
	return true
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
