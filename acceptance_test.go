// Copyright (c) 2026 DarthVaderRC.
// SPDX-License-Identifier: MPL-2.0

package salesforce

import (
	"context"
	"os"
	"testing"

	"github.com/DarthVaderRC/vault-plugin-secrets-salesforce/internal/sftest"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestConfig_ReadNotFound(t *testing.T) {
	b, storage := testBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "config/missing", Storage: storage,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp != nil && !resp.IsError() && len(resp.Data) != 0 {
		t.Errorf("expected empty/error response for missing config, got %v", resp)
	}
}

func TestRole_ReadNotFound(t *testing.T) {
	b, storage := testBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "roles/missing", Storage: storage,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp != nil && !resp.IsError() && len(resp.Data) != 0 {
		t.Errorf("expected empty/error response for missing role, got %v", resp)
	}
}

// TestAcceptance_FullLifecycle exercises the complete engine lifecycle in one
// scenario: configure -> define role -> issue -> cache -> rotate -> renew ->
// revoke. Gated behind VAULT_ACC so it runs as part of `make testacc`.
func TestAcceptance_FullLifecycle(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.Skip("acceptance test; set VAULT_ACC=1 to run")
	}
	m := sftest.New()
	defer m.Close()
	b, storage := testBackend(t)
	ctx := context.Background()

	req := func(r *logical.Request) *logical.Response {
		t.Helper()
		r.Storage = storage
		resp, err := b.HandleRequest(ctx, r)
		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("%s %s failed: err=%v resp=%v", r.Operation, r.Path, err, resp)
		}
		return resp
	}

	req(&logical.Request{Operation: logical.CreateOperation, Path: "config/acme", Data: map[string]interface{}{
		"login_url": m.URL(), "token_url": m.TokenURL(), "client_id": "cid", "client_secret": "secret",
		"allow_non_salesforce_host": true,
	}})
	req(&logical.Request{Operation: logical.CreateOperation, Path: "roles/cc", Data: map[string]interface{}{
		"config": "acme", "grant_type": "client_credentials", "token_ttl": "15m", "ttl": "10m", "max_ttl": "1h",
	}})

	// issue -> cache
	first := req(&logical.Request{Operation: logical.ReadOperation, Path: "creds/cc"})
	if first.Data["cached"] != false {
		t.Errorf("first read should not be cached")
	}
	second := req(&logical.Request{Operation: logical.ReadOperation, Path: "creds/cc"})
	if second.Data["cached"] != true {
		t.Errorf("second read should be cached")
	}
	if m.MintCount() != 1 {
		t.Errorf("expected 1 mint with caching, got %d", m.MintCount())
	}

	// rotate -> fresh mint
	req(&logical.Request{Operation: logical.UpdateOperation, Path: "roles/cc/rotate"})
	if m.MintCount() != 2 {
		t.Errorf("rotate should mint, got %d", m.MintCount())
	}

	// renew -> no mint
	issued := req(&logical.Request{Operation: logical.ReadOperation, Path: "creds/cc"})
	req(&logical.Request{Operation: logical.RenewOperation, Path: "creds/cc", Secret: issued.Secret})
	if m.MintCount() != 2 {
		t.Errorf("renew should not mint, got %d", m.MintCount())
	}

	// revoke -> clears cache
	req(&logical.Request{Operation: logical.RevokeOperation, Path: "creds/cc", Secret: issued.Secret})
	if ct, _ := b.getCachedToken(ctx, storage, "cc"); ct != nil {
		t.Errorf("cache should be cleared after revoke")
	}
}
