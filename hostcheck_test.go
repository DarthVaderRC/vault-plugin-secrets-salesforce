// Copyright (c) 2026 DarthVaderRC.
// SPDX-License-Identifier: MPL-2.0

package salesforce

import (
	"context"
	"strings"
	"testing"

	"github.com/DarthVaderRC/vault-plugin-secrets-salesforce/internal/sftest"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestValidateTokenHost(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		allow   bool
		wantErr bool
	}{
		{"login.salesforce.com", "https://login.salesforce.com/services/oauth2/token", false, false},
		{"test.salesforce.com", "https://test.salesforce.com/services/oauth2/token", false, false},
		{"my domain", "https://acme.my.salesforce.com/services/oauth2/token", false, false},
		{"force.com", "https://acme.force.com/services/oauth2/token", false, false},
		{"loopback http allowed", "http://127.0.0.1:8080/services/oauth2/token", false, false},
		{"localhost allowed", "http://localhost:9000/x", false, false},
		{"evil host rejected", "https://evil.example.com/services/oauth2/token", false, true},
		{"evil host allowed with opt-out", "https://evil.example.com/token", true, false},
		{"http non-loopback rejected", "http://acme.my.salesforce.com/token", false, true},
		{"lookalike suffix rejected", "https://salesforce.com.evil.io/token", false, true},
		{"no host", "/relative/path", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTokenHost(tc.url, tc.allow)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateTokenHost(%q, allow=%v) err=%v, wantErr=%v", tc.url, tc.allow, err, tc.wantErr)
			}
		})
	}
}

func TestConfig_RejectsNonSalesforceHost(t *testing.T) {
	b, storage := testBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation, Path: "config/bad", Storage: storage,
		Data: map[string]interface{}{
			"login_url": "https://evil.example.com", "client_id": "cid", "client_secret": "s",
		},
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected error rejecting non-Salesforce host, got %v", resp)
	}
}

func TestConfig_AllowsNonSalesforceHostWithOptOut(t *testing.T) {
	b, storage := testBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation, Path: "config/gw", Storage: storage,
		Data: map[string]interface{}{
			"login_url": "https://gw.internal.example.com", "client_id": "cid", "client_secret": "s",
			"allow_non_salesforce_host": true,
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("opt-out config should succeed: err=%v resp=%v", err, resp)
	}
}

// TestNoSecretLeakInTokenErrors ensures the client_secret never appears in an
// error surfaced from a failed token request.
func TestNoSecretLeakInTokenErrors(t *testing.T) {
	m := sftest.New()
	defer m.Close()
	m.SetFailMode("invalid_client")
	const secret = "super-secret-value-12345"

	cfg := &salesforceConfig{LoginURL: m.URL(), TokenURL: m.TokenURL(), ClientID: "cid", ClientSecret: secret}
	role := &salesforceRole{GrantType: grantClientCredential}

	_, err := requestClientCredentialsToken(context.Background(), cfg, role)
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), secret) {
		t.Errorf("error leaked the client_secret: %q", err.Error())
	}
}
