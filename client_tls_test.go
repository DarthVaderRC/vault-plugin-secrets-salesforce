package salesforce

import (
	"context"
	"testing"
)

func TestHTTPClientFor(t *testing.T) {
	t.Run("default no ca_cert", func(t *testing.T) {
		c, err := httpClientFor(&salesforceConfig{})
		if err != nil || c == nil {
			t.Fatalf("unexpected: c=%v err=%v", c, err)
		}
	})
	t.Run("tls skip verify", func(t *testing.T) {
		if _, err := httpClientFor(&salesforceConfig{TLSSkipVerify: true}); err != nil {
			t.Fatalf("unexpected err: %v", err)
		}
	})
	t.Run("invalid ca_cert PEM errors", func(t *testing.T) {
		if _, err := httpClientFor(&salesforceConfig{CACert: "not a pem"}); err == nil {
			t.Fatal("expected error for invalid ca_cert")
		}
	})
}

func TestJWTBearer_BadKeyErrors(t *testing.T) {
	cfg := &salesforceConfig{LoginURL: "https://x.my.salesforce.com", ClientID: "cid", PrivateKey: "not-a-key"}
	role := &salesforceRole{GrantType: grantJWTBearer, Username: "u@example.com"}
	if _, err := requestJWTBearerToken(context.Background(), cfg, role); err == nil {
		t.Fatal("expected error when private key is invalid")
	}
}
