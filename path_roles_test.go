// Copyright (c) 2026 DarthVaderRC.
// SPDX-License-Identifier: MPL-2.0

package salesforce

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// seedConfig writes a config named "acme" with the given secret material for role tests.
func seedConfig(t *testing.T, b *backend, storage logical.Storage, data map[string]interface{}) {
	t.Helper()
	base := map[string]interface{}{
		"login_url": "https://acme.my.salesforce.com",
		"client_id": "cid",
	}
	for k, v := range data {
		base[k] = v
	}
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation, Path: "config/acme", Storage: storage, Data: base,
	}); err != nil {
		t.Fatalf("seedConfig failed: %v", err)
	}
}

func writeRole(t *testing.T, b *backend, storage logical.Storage, name string, data map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation, Path: "roles/" + name, Storage: storage, Data: data,
	})
}

func TestRole_JWTBearer_Valid(t *testing.T) {
	b, storage := testBackend(t)
	seedConfig(t, b, storage, map[string]interface{}{"private_key": "PEMKEY"})

	resp, err := writeRole(t, b, storage, "svc", map[string]interface{}{
		"config": "acme", "grant_type": "jwt_bearer", "username": "u@acme.com", "scopes": "api",
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("valid jwt_bearer role rejected: err=%v resp=%v", err, resp)
	}

	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "roles/svc", Storage: storage,
	})
	if err != nil || resp == nil {
		t.Fatalf("read role failed: err=%v resp=%v", err, resp)
	}
	if resp.Data["grant_type"] != "jwt_bearer" {
		t.Errorf("grant_type = %v, want jwt_bearer", resp.Data["grant_type"])
	}
	if resp.Data["token_ttl"].(int64) != 900 {
		t.Errorf("token_ttl default = %v, want 900", resp.Data["token_ttl"])
	}
	if resp.Data["renew_skew"].(int64) != 60 {
		t.Errorf("renew_skew default = %v, want 60", resp.Data["renew_skew"])
	}
}

func TestRole_JWTBearer_RequiresUsername(t *testing.T) {
	b, storage := testBackend(t)
	seedConfig(t, b, storage, map[string]interface{}{"private_key": "PEMKEY"})

	resp, _ := writeRole(t, b, storage, "svc", map[string]interface{}{
		"config": "acme", "grant_type": "jwt_bearer",
	})
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error for missing username, got %v", resp)
	}
}

func TestRole_JWTBearer_RequiresPrivateKey(t *testing.T) {
	b, storage := testBackend(t)
	seedConfig(t, b, storage, nil) // no private_key

	resp, _ := writeRole(t, b, storage, "svc", map[string]interface{}{
		"config": "acme", "grant_type": "jwt_bearer", "username": "u@acme.com",
	})
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error for config without private_key, got %v", resp)
	}
}

func TestRole_ClientCredentials_RequiresClientSecret(t *testing.T) {
	b, storage := testBackend(t)
	seedConfig(t, b, storage, nil) // no client_secret

	resp, _ := writeRole(t, b, storage, "svc", map[string]interface{}{
		"config": "acme", "grant_type": "client_credentials",
	})
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error for config without client_secret, got %v", resp)
	}
}

func TestRole_ClientCredentials_Valid(t *testing.T) {
	b, storage := testBackend(t)
	seedConfig(t, b, storage, map[string]interface{}{"client_secret": "shh"})

	resp, err := writeRole(t, b, storage, "svc", map[string]interface{}{
		"config": "acme", "grant_type": "client_credentials", "scopes": "api",
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("valid client_credentials role rejected: err=%v resp=%v", err, resp)
	}
}

func TestRole_RejectsUnknownGrant(t *testing.T) {
	b, storage := testBackend(t)
	seedConfig(t, b, storage, map[string]interface{}{"client_secret": "shh"})

	resp, _ := writeRole(t, b, storage, "svc", map[string]interface{}{
		"config": "acme", "grant_type": "password",
	})
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error for unknown grant_type, got %v", resp)
	}
}

func TestRole_RejectsMissingConfig(t *testing.T) {
	b, storage := testBackend(t)

	resp, _ := writeRole(t, b, storage, "svc", map[string]interface{}{
		"config": "nope", "grant_type": "client_credentials",
	})
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error for nonexistent config, got %v", resp)
	}
}

func TestRole_RejectsJWTExpiryTooLong(t *testing.T) {
	b, storage := testBackend(t)
	seedConfig(t, b, storage, map[string]interface{}{"private_key": "PEMKEY"})

	resp, _ := writeRole(t, b, storage, "svc", map[string]interface{}{
		"config": "acme", "grant_type": "jwt_bearer", "username": "u@acme.com", "jwt_expiry": "10m",
	})
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error for jwt_expiry > 5m, got %v", resp)
	}
}

func TestRole_RejectsTTLOverMax(t *testing.T) {
	b, storage := testBackend(t)
	seedConfig(t, b, storage, map[string]interface{}{"client_secret": "shh"})

	resp, _ := writeRole(t, b, storage, "svc", map[string]interface{}{
		"config": "acme", "grant_type": "client_credentials", "ttl": "2h", "max_ttl": "1h",
	})
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error for ttl > max_ttl, got %v", resp)
	}
}

func TestRole_ListAndDelete(t *testing.T) {
	b, storage := testBackend(t)
	seedConfig(t, b, storage, map[string]interface{}{"client_secret": "shh"})

	for _, n := range []string{"a", "b"} {
		if resp, err := writeRole(t, b, storage, n, map[string]interface{}{
			"config": "acme", "grant_type": "client_credentials",
		}); err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("write role %s failed: err=%v resp=%v", n, err, resp)
		}
	}

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation, Path: "roles/", Storage: storage,
	})
	if err != nil || resp == nil {
		t.Fatalf("list failed: err=%v resp=%v", err, resp)
	}
	if keys, _ := resp.Data["keys"].([]string); len(keys) != 2 {
		t.Errorf("list keys = %v, want 2", resp.Data["keys"])
	}

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation, Path: "roles/a", Storage: storage,
	}); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if role, _ := b.getRole(context.Background(), storage, "a"); role != nil {
		t.Errorf("role a still present after delete")
	}
}
