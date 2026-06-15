package salesforce

import (
	"context"
	"testing"
	"time"

	"github.com/DarthVaderRC/vault-plugin-secrets-salesforce/internal/sftest"
	"github.com/hashicorp/vault/sdk/logical"
)

// setupCC wires a backend with a config + client_credentials role pointed at the
// given mock server.
func setupCC(t *testing.T, m *sftest.MockServer, tokenTTL string) (*backend, logical.Storage) {
	t.Helper()
	b, storage := testBackend(t)
	ctx := context.Background()

	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "config/acme", Storage: storage,
		Data: map[string]interface{}{
			"login_url": m.URL(), "token_url": m.TokenURL(),
			"client_id": "cid", "client_secret": "secret",
		},
	}); err != nil {
		t.Fatalf("config write failed: %v", err)
	}

	data := map[string]interface{}{"config": "acme", "grant_type": "client_credentials", "scopes": "api"}
	if tokenTTL != "" {
		data["token_ttl"] = tokenTTL
	}
	if resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "roles/cc", Storage: storage, Data: data,
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role write failed: err=%v resp=%v", err, resp)
	}
	return b, storage
}

func readCreds(t *testing.T, b *backend, storage logical.Storage) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/cc", Storage: storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("creds read failed: err=%v resp=%v", err, resp)
	}
	return resp
}

func TestCreds_ClientCredentials_IssuesToken(t *testing.T) {
	m := sftest.New()
	defer m.Close()
	b, storage := setupCC(t, m, "15m")

	resp := readCreds(t, b, storage)

	if resp.Data["access_token"] == "" || resp.Data["access_token"] == nil {
		t.Errorf("no access_token returned: %v", resp.Data)
	}
	if resp.Data["grant_type"] != "client_credentials" {
		t.Errorf("grant_type = %v", resp.Data["grant_type"])
	}
	if resp.Data["cached"] != false {
		t.Errorf("first read should not be cached, got cached=%v", resp.Data["cached"])
	}
	if resp.Secret == nil {
		t.Fatalf("expected a lease secret, got nil")
	}
	if resp.Secret.InternalData["role"] != "cc" {
		t.Errorf("lease role internal data = %v, want cc", resp.Secret.InternalData["role"])
	}
}

func TestCreds_SecondReadIsCached(t *testing.T) {
	m := sftest.New()
	defer m.Close()
	b, storage := setupCC(t, m, "15m")

	first := readCreds(t, b, storage)
	second := readCreds(t, b, storage)

	if second.Data["cached"] != true {
		t.Errorf("second read should be cached, got cached=%v", second.Data["cached"])
	}
	if first.Data["access_token"] != second.Data["access_token"] {
		t.Errorf("cached token differs: %v vs %v", first.Data["access_token"], second.Data["access_token"])
	}
	if m.MintCount() != 1 {
		t.Errorf("expected exactly 1 mint with caching, got %d", m.MintCount())
	}
}

func TestCreds_RemintsWhenStale(t *testing.T) {
	m := sftest.New()
	defer m.Close()
	// token_ttl is 1s and renew_skew default is 60s, so the token is considered
	// stale immediately and every read re-mints.
	b, storage := setupCC(t, m, "1s")

	readCreds(t, b, storage)
	readCreds(t, b, storage)

	if m.MintCount() < 2 {
		t.Errorf("expected re-mint when stale, got %d mints", m.MintCount())
	}
}

func TestCreds_RevokeClearsCache(t *testing.T) {
	m := sftest.New()
	defer m.Close()
	b, storage := setupCC(t, m, "15m")

	resp := readCreds(t, b, storage)
	if ct, _ := b.getCachedToken(context.Background(), storage, "cc"); ct == nil {
		t.Fatal("expected cached token after read")
	}

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Path:      "creds/cc",
		Storage:   storage,
		Secret:    resp.Secret,
	})
	if err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if ct, _ := b.getCachedToken(context.Background(), storage, "cc"); ct != nil {
		t.Errorf("cache not cleared after revoke")
	}
}

func TestCreds_UnknownRole(t *testing.T) {
	b, storage := testBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/missing", Storage: storage,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Errorf("expected error for unknown role, got %v", resp)
	}
}

func TestCreds_ExpiryUsesTokenTTL(t *testing.T) {
	m := sftest.New()
	defer m.Close()
	b, storage := setupCC(t, m, "10m")

	resp := readCreds(t, b, storage)
	expiresAt, err := time.Parse(time.RFC3339, resp.Data["expires_at"].(string))
	if err != nil {
		t.Fatalf("parse expires_at: %v", err)
	}
	want := time.Now().Add(10 * time.Minute)
	if diff := expiresAt.Sub(want); diff > time.Minute || diff < -time.Minute {
		t.Errorf("expires_at = %v, want ~%v (token_ttl-derived)", expiresAt, want)
	}
}
