package salesforce

import (
	"context"
	"fmt"
	"sync"
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

// TestCreds_ConcurrentReadsMintOnce verifies the per-role mint lock prevents a
// stampede: a burst of concurrent reads on a cold cache results in exactly one
// token request to Salesforce.
func TestCreds_ConcurrentReadsMintOnce(t *testing.T) {
	m := sftest.New()
	defer m.Close()
	m.SetMintDelay(50 * time.Millisecond) // widen the race window
	b, storage := setupCC(t, m, "15m")

	const n = 25
	var wg sync.WaitGroup
	tokens := make([]string, n)
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			resp, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.ReadOperation, Path: "creds/cc", Storage: storage,
			})
			if err != nil || resp == nil || resp.IsError() {
				errs[i] = fmt.Errorf("read %d failed: err=%v resp=%v", i, err, resp)
				return
			}
			tokens[i], _ = resp.Data["access_token"].(string)
		}(i)
	}
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := m.MintCount(); got != 1 {
		t.Errorf("expected exactly 1 mint under concurrency, got %d", got)
	}
	for i, tok := range tokens {
		if tok == "" || tok != tokens[0] {
			t.Errorf("read %d token = %q, want all reads to share %q", i, tok, tokens[0])
		}
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

// TestCreds_ServesStaleCacheWhenMintFails verifies graceful degradation: when a
// token is past its renew-skew window (so a read tries to re-mint) but not yet
// truly expired, and minting fails, the engine keeps serving the still-valid
// cached token instead of erroring.
func TestCreds_ServesStaleCacheWhenMintFails(t *testing.T) {
	m := sftest.New()
	defer m.Close()
	// token_ttl 30s with the default 60s renew_skew => the token is "stale"
	// immediately (every read tries to re-mint) but stays valid for ~30s.
	b, storage := setupCC(t, m, "30s")

	first := readCreds(t, b, storage)
	firstToken := first.Data["access_token"].(string)

	// Salesforce now rejects mints (non-retryable, fails fast).
	m.SetFailMode("invalid_client")

	resp := readCreds(t, b, storage) // must NOT error
	if resp.Data["access_token"] != firstToken {
		t.Errorf("expected still-valid cached token %q, got %v", firstToken, resp.Data["access_token"])
	}
	if resp.Data["cached"] != true {
		t.Errorf("fallback token should be reported cached, got %v", resp.Data["cached"])
	}
}

// TestCreds_ErrorsWhenMintFailsAndNoValidCache verifies that without a usable
// cached token, a mint failure surfaces as an error.
func TestCreds_ErrorsWhenMintFailsAndNoValidCache(t *testing.T) {
	m := sftest.New()
	defer m.Close()
	m.SetFailMode("invalid_client")
	b, storage := setupCC(t, m, "15m")

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/cc", Storage: storage,
	})
	if err == nil && (resp == nil || !resp.IsError()) {
		t.Fatalf("expected an error when minting fails with no cache, got resp=%v err=%v", resp, err)
	}
}
