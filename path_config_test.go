package salesforce

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// testBackend returns a configured backend with in-memory storage for tests.
func testBackend(t *testing.T) (*backend, logical.Storage) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("Factory error: %v", err)
	}
	return b.(*backend), config.StorageView
}

func TestConfig_WriteReadRedactsSecrets(t *testing.T) {
	b, storage := testBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/acme",
		Storage:   storage,
		Data: map[string]interface{}{
			"login_url":     "https://acme.my.salesforce.com",
			"client_id":     "3MVG9abc",
			"client_secret": "super-secret",
			"private_key":   "-----BEGIN RSA PRIVATE KEY-----\nMII...\n-----END RSA PRIVATE KEY-----",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("write failed: err=%v resp=%v", err, resp)
	}

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config/acme",
		Storage:   storage,
	})
	if err != nil || resp == nil {
		t.Fatalf("read failed: err=%v resp=%v", err, resp)
	}

	if got := resp.Data["client_id"]; got != "3MVG9abc" {
		t.Errorf("client_id = %v, want 3MVG9abc", got)
	}
	if got := resp.Data["client_secret"]; got != redactedValue {
		t.Errorf("client_secret = %v, want %s", got, redactedValue)
	}
	if got := resp.Data["private_key"]; got != redactedValue {
		t.Errorf("private_key = %v, want %s", got, redactedValue)
	}
	if got := resp.Data["token_url"]; got != "https://acme.my.salesforce.com/services/oauth2/token" {
		t.Errorf("token_url = %v, want default-derived endpoint", got)
	}
}

func TestConfig_StoredSecretsAreIntact(t *testing.T) {
	b, storage := testBackend(t)
	ctx := context.Background()

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/acme",
		Storage:   storage,
		Data: map[string]interface{}{
			"login_url":     "https://acme.my.salesforce.com",
			"client_id":     "cid",
			"client_secret": "the-secret",
		},
	})
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}

	cfg, err := b.getConfig(ctx, storage, "acme")
	if err != nil || cfg == nil {
		t.Fatalf("getConfig failed: err=%v cfg=%v", err, cfg)
	}
	if cfg.ClientSecret != "the-secret" {
		t.Errorf("stored client_secret = %q, want the-secret (redaction must not corrupt storage)", cfg.ClientSecret)
	}
}

func TestConfig_RequiredFields(t *testing.T) {
	b, storage := testBackend(t)
	ctx := context.Background()

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config/x",
		Storage:   storage,
		Data:      map[string]interface{}{"client_id": "cid"},
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error response for missing login_url, got %v", resp)
	}
}

func TestConfig_Update_PreservesSecrets(t *testing.T) {
	b, storage := testBackend(t)
	ctx := context.Background()

	write := func(data map[string]interface{}, op logical.Operation) {
		t.Helper()
		if _, err := b.HandleRequest(ctx, &logical.Request{
			Operation: op, Path: "config/acme", Storage: storage, Data: data,
		}); err != nil {
			t.Fatalf("write failed: %v", err)
		}
	}

	write(map[string]interface{}{
		"login_url": "https://acme.my.salesforce.com", "client_id": "cid", "client_secret": "secret1",
	}, logical.CreateOperation)
	// Update only login_url; client_secret must persist.
	write(map[string]interface{}{"login_url": "https://acme.my.salesforce.com"}, logical.UpdateOperation)

	cfg, _ := b.getConfig(ctx, storage, "acme")
	if cfg.ClientSecret != "secret1" {
		t.Errorf("client_secret after partial update = %q, want secret1", cfg.ClientSecret)
	}
}

func TestConfig_ListAndDelete(t *testing.T) {
	b, storage := testBackend(t)
	ctx := context.Background()

	for _, n := range []string{"a", "b"} {
		if _, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation, Path: "config/" + n, Storage: storage,
			Data: map[string]interface{}{"login_url": "https://x.my.salesforce.com", "client_id": "cid"},
		}); err != nil {
			t.Fatalf("write %s failed: %v", n, err)
		}
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation, Path: "config/", Storage: storage,
	})
	if err != nil || resp == nil {
		t.Fatalf("list failed: err=%v resp=%v", err, resp)
	}
	keys, _ := resp.Data["keys"].([]string)
	if len(keys) != 2 {
		t.Errorf("list keys = %v, want 2 entries", keys)
	}

	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation, Path: "config/a", Storage: storage,
	}); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	cfg, _ := b.getConfig(ctx, storage, "a")
	if cfg != nil {
		t.Errorf("config/a still present after delete")
	}
}
