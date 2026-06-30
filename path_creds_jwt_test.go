// Copyright (c) 2026 DarthVaderRC.
// SPDX-License-Identifier: MPL-2.0

package salesforce

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/DarthVaderRC/vault-plugin-secrets-salesforce/internal/sftest"
	"github.com/golang-jwt/jwt/v5"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestCreds_JWTBearer_EndToEnd(t *testing.T) {
	// Generate a key; the mock validates the assertion with the public key.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))

	m := sftest.New()
	defer m.Close()
	m.SetAssertionValidator(func(assertion string) error {
		parsed, err := jwt.Parse(assertion, func(*jwt.Token) (interface{}, error) {
			return &key.PublicKey, nil
		})
		if err != nil || !parsed.Valid {
			return fmt.Errorf("assertion invalid: %v", err)
		}
		claims := parsed.Claims.(jwt.MapClaims)
		if claims["sub"] != "svc@acme.com" {
			return fmt.Errorf("sub = %v, want svc@acme.com", claims["sub"])
		}
		if claims["iss"] != "consumer-key" {
			return fmt.Errorf("iss = %v, want consumer-key", claims["iss"])
		}
		return nil
	})

	b, storage := testBackend(t)
	ctx := context.Background()

	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "config/jorg", Storage: storage,
		Data: map[string]interface{}{
			"login_url": m.URL(), "token_url": m.TokenURL(),
			"client_id": "consumer-key", "private_key": keyPEM,
			"allow_non_salesforce_host": true,
		},
	}); err != nil {
		t.Fatalf("config write: %v", err)
	}

	if resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "roles/jrole", Storage: storage,
		Data: map[string]interface{}{
			"config": "jorg", "grant_type": "jwt_bearer",
			"username": "svc@acme.com", "scopes": "api",
		},
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role write: err=%v resp=%v", err, resp)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/jrole", Storage: storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("creds read: err=%v resp=%v", err, resp)
	}

	if resp.Data["grant_type"] != "jwt_bearer" {
		t.Errorf("grant_type = %v, want jwt_bearer", resp.Data["grant_type"])
	}
	if resp.Data["access_token"] == "" || resp.Data["access_token"] == nil {
		t.Errorf("no access_token returned")
	}
	if resp.Secret == nil || resp.Secret.InternalData["role"] != "jrole" {
		t.Errorf("expected lease secret bound to role jrole, got %+v", resp.Secret)
	}

	// Second read should be cached (one mint).
	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/jrole", Storage: storage,
	}); err != nil {
		t.Fatalf("second creds read: %v", err)
	}
	if m.MintCount() != 1 {
		t.Errorf("expected 1 mint with caching, got %d", m.MintCount())
	}
}

func TestCreds_JWTBearer_RejectedAssertion(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))

	m := sftest.New()
	defer m.Close()
	// Reject everything, simulating "user hasn't approved this consumer".
	m.SetFailMode("invalid_grant")

	b, storage := testBackend(t)
	ctx := context.Background()
	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "config/jorg", Storage: storage,
		Data: map[string]interface{}{
			"login_url": m.URL(), "token_url": m.TokenURL(),
			"client_id": "ck", "private_key": keyPEM,
			"allow_non_salesforce_host": true,
		},
	}); err != nil {
		t.Fatalf("config write: %v", err)
	}
	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "roles/jrole", Storage: storage,
		Data: map[string]interface{}{"config": "jorg", "grant_type": "jwt_bearer", "username": "u@acme.com"},
	}); err != nil {
		t.Fatalf("role write: %v", err)
	}

	_, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation, Path: "creds/jrole", Storage: storage,
	})
	if err == nil {
		t.Fatal("expected error from rejected assertion")
	}
}
