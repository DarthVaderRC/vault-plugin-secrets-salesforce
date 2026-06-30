// Copyright (c) 2026 DarthVaderRC.
// SPDX-License-Identifier: MPL-2.0

package salesforce

import (
	"crypto/rsa"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// rsaKeyCache memoizes parsed RSA private keys by their PEM text so the key is
// not re-parsed on every mint (a CPU amplifier under load).
var rsaKeyCache sync.Map // map[string]*rsa.PrivateKey

// buildJWTAssertion creates and RS256-signs the JWT bearer assertion for a role.
// Claims follow the Salesforce JWT Bearer flow:
//
//	iss = client_id (Consumer Key)
//	sub = username (run-as identity)
//	aud = login host (or role.Audience override)
//	exp = now + jwt_expiry (Salesforce rejects assertions too far in the future)
func buildJWTAssertion(cfg *salesforceConfig, role *salesforceRole, now time.Time) (string, error) {
	key, err := parseRSAPrivateKey(cfg.PrivateKey)
	if err != nil {
		return "", err
	}

	audience := role.Audience
	if audience == "" {
		audience = strings.TrimRight(cfg.LoginURL, "/")
	}

	expiry := role.JWTExpiry
	if expiry <= 0 {
		expiry = 3 * time.Minute
	}

	claims := jwt.MapClaims{
		"iss": cfg.ClientID,
		"sub": role.Username,
		"aud": audience,
		"exp": now.Add(expiry).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("signing jwt assertion: %w", err)
	}
	return signed, nil
}

// parseRSAPrivateKey parses a PEM-encoded RSA private key in PKCS#1 or PKCS#8.
func parseRSAPrivateKey(pemKey string) (*rsa.PrivateKey, error) {
	if strings.TrimSpace(pemKey) == "" {
		return nil, fmt.Errorf("no private_key configured")
	}
	if cached, ok := rsaKeyCache.Load(pemKey); ok {
		return cached.(*rsa.PrivateKey), nil
	}
	key, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(pemKey))
	if err != nil {
		return nil, fmt.Errorf("parsing RSA private key: %w", err)
	}
	rsaKeyCache.Store(pemKey, key)
	return key, nil
}
