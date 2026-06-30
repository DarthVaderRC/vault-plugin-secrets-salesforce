// Copyright (c) 2026 DarthVaderRC.
// SPDX-License-Identifier: MPL-2.0

package salesforce

import (
	"context"
	"testing"
	"time"

	"github.com/DarthVaderRC/vault-plugin-secrets-salesforce/internal/sftest"
	"github.com/hashicorp/vault/sdk/logical"
)

// writeConfig is a small helper that issues a config write and returns the response.
func writeConfig(t *testing.T, b *backend, storage logical.Storage, name string, op logical.Operation, data map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: op, Path: "config/" + name, Storage: storage, Data: data,
	})
}

// TestConfig_RepointWithoutResupplyingSecretRejected verifies that an update
// which repoints the token endpoint (or relaxes a transport guard) is rejected
// unless the secret material is re-supplied. This closes the secret-exfiltration
// path where an update-only principal repoints the destination.
func TestConfig_RepointWithoutResupplyingSecretRejected(t *testing.T) {
	b, storage := testBackend(t)

	// Seed a config holding a client_secret on a real Salesforce host.
	if resp, err := writeConfig(t, b, storage, "acme", logical.CreateOperation, map[string]interface{}{
		"login_url": "https://acme.my.salesforce.com", "client_id": "cid", "client_secret": "shh",
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("seed config failed: err=%v resp=%v", err, resp)
	}

	cases := []struct {
		name string
		data map[string]interface{}
	}{
		{"repoint token_url", map[string]interface{}{"login_url": "https://acme.my.salesforce.com", "token_url": "https://evil.example.com/token", "allow_non_salesforce_host": true}},
		{"relax allow_non_salesforce_host", map[string]interface{}{"login_url": "https://acme.my.salesforce.com", "allow_non_salesforce_host": true}},
		{"enable tls_skip_verify", map[string]interface{}{"login_url": "https://acme.my.salesforce.com", "tls_skip_verify": true}},
		{"change login_url host", map[string]interface{}{"login_url": "https://other.my.salesforce.com"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := writeConfig(t, b, storage, "acme", logical.UpdateOperation, tc.data)
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if resp == nil || !resp.IsError() {
				t.Fatalf("expected rejection without re-supplying secret, got %v", resp)
			}
		})
	}
}

// TestConfig_RepointWithResupplyingSecretAllowed verifies the same change is
// accepted when the secret is re-supplied in the request.
func TestConfig_RepointWithResupplyingSecretAllowed(t *testing.T) {
	b, storage := testBackend(t)
	if resp, err := writeConfig(t, b, storage, "acme", logical.CreateOperation, map[string]interface{}{
		"login_url": "https://acme.my.salesforce.com", "client_id": "cid", "client_secret": "shh",
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("seed config failed: err=%v resp=%v", err, resp)
	}
	resp, err := writeConfig(t, b, storage, "acme", logical.UpdateOperation, map[string]interface{}{
		"login_url": "https://acme.my.salesforce.com", "token_url": "https://gw.internal.example.com/token",
		"allow_non_salesforce_host": true, "client_secret": "shh",
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("re-supplying the secret should permit the repoint: err=%v resp=%v", err, resp)
	}
}

// TestConfig_NonSensitiveUpdateWithoutSecretAllowed ensures a benign update
// (e.g. ca_cert) does not require re-supplying the secret.
func TestConfig_NonSensitiveUpdateWithoutSecretAllowed(t *testing.T) {
	b, storage := testBackend(t)
	if resp, err := writeConfig(t, b, storage, "acme", logical.CreateOperation, map[string]interface{}{
		"login_url": "https://acme.my.salesforce.com", "client_id": "cid", "client_secret": "shh",
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("seed config failed: err=%v resp=%v", err, resp)
	}
	resp, err := writeConfig(t, b, storage, "acme", logical.UpdateOperation, map[string]interface{}{
		"login_url": "https://acme.my.salesforce.com", "client_id": "cid2",
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("benign update should succeed without re-supplying secret: err=%v resp=%v", err, resp)
	}
}

// TestRole_UsernameAndConfigImmutable verifies the Salesforce identity and the
// bound config cannot be repointed on update.
func TestRole_UsernameAndConfigImmutable(t *testing.T) {
	b, storage := testBackend(t)
	seedConfig(t, b, storage, map[string]interface{}{"private_key": "PEMKEY"})
	// A second config for the rebind attempt.
	if resp, err := writeConfig(t, b, storage, "other", logical.CreateOperation, map[string]interface{}{
		"login_url": "https://other.my.salesforce.com", "client_id": "cid", "private_key": "PEMKEY",
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("seed other config failed: err=%v resp=%v", err, resp)
	}

	if resp, err := writeRole(t, b, storage, "jr", map[string]interface{}{
		"config": "acme", "grant_type": "jwt_bearer", "username": "svc@acme.com",
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role create failed: err=%v resp=%v", err, resp)
	}

	update := func(data map[string]interface{}) *logical.Response {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation, Path: "roles/jr", Storage: storage, Data: data,
		})
		if err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
		return resp
	}

	if resp := update(map[string]interface{}{"username": "admin@acme.com"}); resp == nil || !resp.IsError() {
		t.Errorf("expected username change to be rejected, got %v", resp)
	}
	if resp := update(map[string]interface{}{"config": "other"}); resp == nil || !resp.IsError() {
		t.Errorf("expected config rebind to be rejected, got %v", resp)
	}
	// An unrelated update (scopes) with the same username/config should succeed.
	if resp := update(map[string]interface{}{"scopes": "api"}); resp != nil && resp.IsError() {
		t.Errorf("benign role update should succeed, got %v", resp)
	}
}

// TestRole_RenewSkewBounds verifies renew_skew is bounded.
func TestRole_RenewSkewBounds(t *testing.T) {
	b, storage := testBackend(t)
	seedConfig(t, b, storage, map[string]interface{}{"client_secret": "shh"})

	// renew_skew >= token_ttl is rejected.
	if resp, _ := writeRole(t, b, storage, "r1", map[string]interface{}{
		"config": "acme", "grant_type": "client_credentials", "token_ttl": "10s", "renew_skew": "30s",
	}); resp == nil || !resp.IsError() {
		t.Errorf("expected renew_skew >= token_ttl to be rejected, got %v", resp)
	}
	// A valid skew is accepted.
	if resp, err := writeRole(t, b, storage, "r2", map[string]interface{}{
		"config": "acme", "grant_type": "client_credentials", "token_ttl": "10s", "renew_skew": "5s",
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Errorf("valid renew_skew should be accepted: err=%v resp=%v", err, resp)
	}
}

// TestRole_UseIntrospectionWarns verifies the reserved field returns a warning.
func TestRole_UseIntrospectionWarns(t *testing.T) {
	b, storage := testBackend(t)
	seedConfig(t, b, storage, map[string]interface{}{"client_secret": "shh"})
	resp, err := writeRole(t, b, storage, "r", map[string]interface{}{
		"config": "acme", "grant_type": "client_credentials", "use_introspection": true,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role write failed: err=%v resp=%v", err, resp)
	}
	if resp == nil || len(resp.Warnings) == 0 {
		t.Fatalf("expected a warning for use_introspection, got %v", resp)
	}
}

// TestConfig_UpdateInvalidatesCachedTokens verifies that updating a config drops
// cached tokens for its bound roles so the next read re-mints under the new config.
func TestConfig_UpdateInvalidatesCachedTokens(t *testing.T) {
	m := sftest.New()
	defer m.Close()
	b, storage := setupCC(t, m, "15m")

	readCreds(t, b, storage) // mint #1, now cached
	if m.MintCount() != 1 {
		t.Fatalf("expected 1 mint, got %d", m.MintCount())
	}

	// Update the bound config (re-supply the secret since this is a sensitive-safe
	// update of client_id only — no endpoint change — but re-supply anyway).
	if resp, err := writeConfig(t, b, storage, "acme", logical.UpdateOperation, map[string]interface{}{
		"login_url": m.URL(), "token_url": m.TokenURL(), "client_id": "cid2",
		"client_secret": "secret", "allow_non_salesforce_host": true,
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config update failed: err=%v resp=%v", err, resp)
	}

	readCreds(t, b, storage) // should re-mint because the cache was invalidated
	if m.MintCount() != 2 {
		t.Errorf("expected re-mint after config update, got %d mints", m.MintCount())
	}
}

// TestCreds_FailsClosedOnDefinitiveOAuthError verifies that a definitive OAuth
// error (invalid_grant) purges the cache and fails the read rather than serving
// the stale token.
func TestCreds_FailsClosedOnDefinitiveOAuthError(t *testing.T) {
	m := sftest.New()
	defer m.Close()
	b, storage := setupCC(t, m, "1s")

	readCreds(t, b, storage) // cache a token
	time.Sleep(1100 * time.Millisecond)

	// Now Salesforce rejects with a definitive error.
	m.SetFailMode("invalid_grant")
	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/cc", Storage: storage,
	})
	if err == nil {
		t.Fatal("expected a definitive OAuth error to fail the read")
	}
	// The cached token must have been purged.
	if ct, _ := b.getCachedToken(context.Background(), storage, "cc"); ct != nil {
		t.Errorf("expected cache to be purged on definitive error, got %v", ct)
	}
}

// TestRevoke_CallsSalesforceWhenOptedIn verifies that revoke_tokens=true makes
// lease revoke and rotate call the Salesforce /revoke endpoint.
func TestRevoke_CallsSalesforceWhenOptedIn(t *testing.T) {
	m := sftest.New()
	defer m.Close()
	b, storage := testBackend(t)
	ctx := context.Background()

	if resp, err := writeConfig(t, b, storage, "acme", logical.CreateOperation, map[string]interface{}{
		"login_url": m.URL(), "token_url": m.TokenURL(), "client_id": "cid", "client_secret": "secret",
		"allow_non_salesforce_host": true,
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write failed: err=%v resp=%v", err, resp)
	}
	if resp, err := writeRole(t, b, storage, "cc", map[string]interface{}{
		"config": "acme", "grant_type": "client_credentials", "token_ttl": "15m", "revoke_tokens": true,
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role write failed: err=%v resp=%v", err, resp)
	}

	issued := readCreds(t, b, storage)
	wantToken := issued.Data["access_token"].(string)

	// Revoke the lease -> should call Salesforce /revoke for the cached token.
	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation, Path: "creds/cc", Storage: storage,
		Secret: &logical.Secret{InternalData: map[string]interface{}{"role": "cc", "secret_type": secretAccessTokenType}},
	}); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if m.RevokeCount() != 1 {
		t.Fatalf("expected 1 revoke call, got %d", m.RevokeCount())
	}
	if got := m.RevokedTokens()[0]; got != wantToken {
		t.Errorf("revoked token = %q, want %q", got, wantToken)
	}
}

// TestRevoke_NotCalledByDefault verifies the default (revoke_tokens=false) does
// not call Salesforce /revoke.
func TestRevoke_NotCalledByDefault(t *testing.T) {
	m := sftest.New()
	defer m.Close()
	b, storage := setupCC(t, m, "15m")
	ctx := context.Background()

	readCreds(t, b, storage)
	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.RevokeOperation, Path: "creds/cc", Storage: storage,
		Secret: &logical.Secret{InternalData: map[string]interface{}{"role": "cc", "secret_type": secretAccessTokenType}},
	}); err != nil {
		t.Fatalf("revoke failed: %v", err)
	}
	if m.RevokeCount() != 0 {
		t.Errorf("expected no revoke call by default, got %d", m.RevokeCount())
	}
}
