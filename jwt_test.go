package salesforce

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func testRSAKeyPEM(t *testing.T) (string, *rsa.PublicKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	return string(pemBytes), &key.PublicKey
}

func TestJWT_SignAndVerify(t *testing.T) {
	keyPEM, pub := testRSAKeyPEM(t)
	cfg := &salesforceConfig{
		LoginURL:   "https://login.salesforce.com/",
		ClientID:   "consumer-key",
		PrivateKey: keyPEM,
	}
	role := &salesforceRole{Username: "user@acme.com", JWTExpiry: 3 * time.Minute}
	now := time.Now()

	assertion, err := buildJWTAssertion(cfg, role, now)
	if err != nil {
		t.Fatalf("buildJWTAssertion: %v", err)
	}

	parsed, err := jwt.Parse(assertion, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != "RS256" {
			t.Errorf("alg = %s, want RS256", token.Method.Alg())
		}
		return pub, nil
	})
	if err != nil || !parsed.Valid {
		t.Fatalf("verify failed: err=%v valid=%v", err, parsed.Valid)
	}

	claims := parsed.Claims.(jwt.MapClaims)
	if claims["iss"] != "consumer-key" {
		t.Errorf("iss = %v, want consumer-key", claims["iss"])
	}
	if claims["sub"] != "user@acme.com" {
		t.Errorf("sub = %v, want user@acme.com", claims["sub"])
	}
	// aud should be the trimmed login URL (no trailing slash).
	if claims["aud"] != "https://login.salesforce.com" {
		t.Errorf("aud = %v, want https://login.salesforce.com", claims["aud"])
	}
}

func TestJWT_AudienceOverride(t *testing.T) {
	keyPEM, pub := testRSAKeyPEM(t)
	cfg := &salesforceConfig{LoginURL: "https://login.salesforce.com", ClientID: "ck", PrivateKey: keyPEM}
	role := &salesforceRole{Username: "u", JWTExpiry: time.Minute, Audience: "https://test.salesforce.com"}

	assertion, err := buildJWTAssertion(cfg, role, time.Now())
	if err != nil {
		t.Fatalf("buildJWTAssertion: %v", err)
	}
	parsed, _ := jwt.Parse(assertion, func(*jwt.Token) (interface{}, error) { return pub, nil })
	if got := parsed.Claims.(jwt.MapClaims)["aud"]; got != "https://test.salesforce.com" {
		t.Errorf("aud = %v, want override https://test.salesforce.com", got)
	}
}

func TestJWT_ExpiryWindow(t *testing.T) {
	keyPEM, pub := testRSAKeyPEM(t)
	cfg := &salesforceConfig{LoginURL: "https://login.salesforce.com", ClientID: "ck", PrivateKey: keyPEM}
	role := &salesforceRole{Username: "u", JWTExpiry: 2 * time.Minute}
	now := time.Now()

	assertion, _ := buildJWTAssertion(cfg, role, now)
	parsed, _ := jwt.Parse(assertion, func(*jwt.Token) (interface{}, error) { return pub, nil })
	expF := parsed.Claims.(jwt.MapClaims)["exp"].(float64)
	want := now.Add(2 * time.Minute).Unix()
	if int64(expF) != want {
		t.Errorf("exp = %d, want %d", int64(expF), want)
	}
}

func TestJWT_RejectsBadKey(t *testing.T) {
	cfg := &salesforceConfig{LoginURL: "https://login.salesforce.com", ClientID: "ck", PrivateKey: "not a pem"}
	role := &salesforceRole{Username: "u", JWTExpiry: time.Minute}
	if _, err := buildJWTAssertion(cfg, role, time.Now()); err == nil {
		t.Fatal("expected error for invalid private key")
	}
}
