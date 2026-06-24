package salesforce

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/DarthVaderRC/vault-plugin-secrets-salesforce/internal/sftest"
)

func TestClient_ClientCredentials_Success(t *testing.T) {
	m := sftest.New()
	defer m.Close()

	cfg := &salesforceConfig{
		LoginURL:     m.URL(),
		TokenURL:     m.TokenURL(),
		ClientID:     "cid",
		ClientSecret: "secret",
	}
	role := &salesforceRole{GrantType: grantClientCredential, Scopes: []string{"api", "web"}}

	res, err := requestClientCredentialsToken(context.Background(), cfg, role)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(res.AccessToken, "00Dxx") {
		t.Errorf("access_token = %q, want a minted token", res.AccessToken)
	}
	if res.InstanceURL == "" {
		t.Errorf("instance_url empty")
	}

	reqs := m.Requests()
	if len(reqs) != 1 {
		t.Fatalf("expected 1 request, got %d", len(reqs))
	}
	got := reqs[0]
	if got["grant_type"] != "client_credentials" {
		t.Errorf("grant_type = %q", got["grant_type"])
	}
	if got["client_id"] != "cid" || got["client_secret"] != "secret" {
		t.Errorf("client credentials not sent correctly: %v", got)
	}
	if _, ok := got["scope"]; ok {
		t.Errorf("scope must NOT be sent for client_credentials (Salesforce rejects it), got %q", got["scope"])
	}
}

func TestClient_ClientCredentials_OAuthError(t *testing.T) {
	m := sftest.New()
	defer m.Close()
	m.SetFailMode("invalid_client")

	cfg := &salesforceConfig{LoginURL: m.URL(), TokenURL: m.TokenURL(), ClientID: "cid", ClientSecret: "bad"}
	role := &salesforceRole{GrantType: grantClientCredential}

	_, err := requestClientCredentialsToken(context.Background(), cfg, role)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	sfErr, ok := err.(*salesforceError)
	if !ok {
		t.Fatalf("error type = %T, want *salesforceError", err)
	}
	if sfErr.Code != "invalid_client" {
		t.Errorf("error code = %q, want invalid_client", sfErr.Code)
	}
	if strings.Contains(err.Error(), "bad") {
		t.Errorf("error message leaked the client_secret: %s", err.Error())
	}
}

func TestClient_ClientCredentials_ServerError(t *testing.T) {
	m := sftest.New()
	defer m.Close()
	m.SetFailMode("server_error")

	cfg := &salesforceConfig{LoginURL: m.URL(), TokenURL: m.TokenURL(), ClientID: "cid", ClientSecret: "s"}
	role := &salesforceRole{GrantType: grantClientCredential}

	_, err := requestClientCredentialsToken(context.Background(), cfg, role)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if sfErr, ok := err.(*salesforceError); !ok || sfErr.StatusCode != 500 {
		t.Errorf("expected 500 salesforceError, got %v", err)
	}
}

func TestClient_RetriesTransientThenSucceeds(t *testing.T) {
	m := sftest.New()
	defer m.Close()
	m.SetTransientFailures(2, 503) // fail twice, then succeed on the 3rd attempt

	old := tokenRetryBaseBackoff
	tokenRetryBaseBackoff = time.Millisecond
	defer func() { tokenRetryBaseBackoff = old }()

	cfg := &salesforceConfig{LoginURL: m.URL(), TokenURL: m.TokenURL(), ClientID: "cid", ClientSecret: "secret"}
	role := &salesforceRole{GrantType: grantClientCredential}

	res, err := requestClientCredentialsToken(context.Background(), cfg, role)
	if err != nil {
		t.Fatalf("expected success after retries, got %v", err)
	}
	if res.AccessToken == "" {
		t.Errorf("no access_token after retries")
	}
	if got := len(m.Requests()); got != 3 {
		t.Errorf("expected 3 token requests (2 fail + 1 success), got %d", got)
	}
	if m.MintCount() != 1 {
		t.Errorf("expected exactly 1 successful mint, got %d", m.MintCount())
	}
}

func TestClient_DoesNotRetryNonTransient(t *testing.T) {
	m := sftest.New()
	defer m.Close()
	m.SetFailMode("invalid_grant") // 400-class error, must not be retried

	old := tokenRetryBaseBackoff
	tokenRetryBaseBackoff = time.Millisecond
	defer func() { tokenRetryBaseBackoff = old }()

	cfg := &salesforceConfig{LoginURL: m.URL(), TokenURL: m.TokenURL(), ClientID: "cid", ClientSecret: "secret"}
	role := &salesforceRole{GrantType: grantClientCredential}

	if _, err := requestClientCredentialsToken(context.Background(), cfg, role); err == nil {
		t.Fatal("expected error for invalid_grant")
	}
	if got := len(m.Requests()); got != 1 {
		t.Errorf("non-transient error must not retry; expected 1 request, got %d", got)
	}
}

func TestClient_RetriesExhaustedReturnsError(t *testing.T) {
	m := sftest.New()
	defer m.Close()
	m.SetTransientFailures(99, 503) // always transient-fail

	old := tokenRetryBaseBackoff
	tokenRetryBaseBackoff = time.Millisecond
	defer func() { tokenRetryBaseBackoff = old }()

	cfg := &salesforceConfig{LoginURL: m.URL(), TokenURL: m.TokenURL(), ClientID: "cid", ClientSecret: "secret"}
	role := &salesforceRole{GrantType: grantClientCredential}

	if _, err := requestClientCredentialsToken(context.Background(), cfg, role); err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if got := len(m.Requests()); got != tokenRetryMaxAttempts {
		t.Errorf("expected %d attempts, got %d", tokenRetryMaxAttempts, got)
	}
}
