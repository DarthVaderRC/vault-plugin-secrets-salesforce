// Copyright (c) 2026 DarthVaderRC.
// SPDX-License-Identifier: MPL-2.0

package salesforce

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCreds(b *backend) []*framework.Path {
	fields := map[string]*framework.FieldSchema{
		"name": {
			Type:        framework.TypeString,
			Description: "Name of the role to issue a token for.",
			Required:    true,
		},
	}
	return []*framework.Path{
		{
			Pattern: "creds/" + framework.GenericNameRegex("name"),
			Fields:  fields,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.pathCredsRead},
			},
			HelpSynopsis:    "Issue a Salesforce OAuth access token for a role.",
			HelpDescription: "Read this path to obtain a short-lived Salesforce access token. Tokens are cached per role and transparently re-minted near expiry.",
		},
		{
			// Alias: token/<name> behaves identically to creds/<name>.
			Pattern: "token/" + framework.GenericNameRegex("name"),
			Fields:  fields,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.pathCredsRead},
			},
			HelpSynopsis:    "Alias of creds/<name>.",
			HelpDescription: "Read this path to obtain a short-lived Salesforce access token (alias of creds/<name>).",
		},
	}
}

func (b *backend) pathCredsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q does not exist", roleName), nil
	}

	cfg, err := b.getConfig(ctx, req.Storage, role.Config)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return logical.ErrorResponse("config %q for role %q does not exist", role.Config, roleName), nil
	}

	token, cached, err := b.issueToken(ctx, req.Storage, roleName, cfg, role)
	if err != nil {
		return nil, err
	}

	resp := b.Secret(secretAccessTokenType).Response(
		map[string]interface{}{
			"access_token": token.AccessToken,
			"instance_url": token.InstanceURL,
			"token_type":   token.TokenType,
			"expires_at":   token.ExpiresAt.UTC().Format(time.RFC3339),
			"grant_type":   role.GrantType,
			"cached":       cached,
		},
		map[string]interface{}{
			"role": roleName,
		},
	)
	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.MaxTTL
	return resp, nil
}

// issueToken returns a usable token for the role, serving the cached one when
// still fresh and otherwise minting a new one and caching it. The bool reports
// whether the returned token came from cache.
//
// Minting is guarded by a per-role lock so that a burst of concurrent reads on
// a cold or expired cache results in a single token request to Salesforce (the
// rest observe the freshly cached token), rather than a mint stampede.
func (b *backend) issueToken(ctx context.Context, s logical.Storage, roleName string, cfg *salesforceConfig, role *salesforceRole) (*cachedToken, bool, error) {
	// Fast path: serve a fresh cached token without taking the mint lock.
	if ct, err := b.getCachedToken(ctx, s, roleName); err != nil {
		return nil, false, err
	} else if ct != nil && ct.fresh(time.Now(), role.RenewSkew) {
		return ct, true, nil
	}

	// Slow path: serialize minting per role. Avoid head-of-line blocking: if
	// another goroutine is already minting for this role and we still hold a
	// usable (pre-expiry) cached token, serve it rather than block on the mint
	// round-trip. Only a cold/expired cache waits for the in-flight mint.
	lock := locksutil.LockForKey(b.locks, roleName)
	if !lock.TryLock() {
		if ct, err := b.getCachedToken(ctx, s, roleName); err == nil && ct != nil && time.Now().Before(ct.ExpiresAt) {
			return ct, true, nil
		}
		lock.Lock()
	}
	defer lock.Unlock()

	// Re-check under the lock: another goroutine may have minted while we waited.
	if ct, err := b.getCachedToken(ctx, s, roleName); err != nil {
		return nil, false, err
	} else if ct != nil && ct.fresh(time.Now(), role.RenewSkew) {
		return ct, true, nil
	}

	ct, err := b.mintAndCache(ctx, s, roleName, cfg, role)
	if err != nil {
		// Graceful degradation, but only for transient failures: if minting
		// fails because Salesforce is briefly unavailable (network/429/5xx) and
		// the previously cached token is still valid, keep serving it.
		existing, gErr := b.getCachedToken(ctx, s, roleName)
		if gErr == nil && existing != nil && time.Now().Before(existing.ExpiresAt) && isTransientMintError(err) {
			b.Logger().Warn("salesforce token mint failed; serving still-valid cached token",
				"role", roleName, "error", err.Error(), "expires_at", existing.ExpiresAt)
			return existing, true, nil
		}
		// Definitive failure (e.g. invalid_grant/invalid_client): the cached
		// token was minted under credentials the server now rejects. Purge it and
		// fail closed instead of handing out a token the server may have revoked.
		if !isTransientMintError(err) {
			if dErr := b.deleteCachedToken(ctx, s, roleName); dErr != nil {
				return nil, false, dErr
			}
		}
		return nil, false, err
	}
	return ct, false, nil
}

// mintAndCache mints a fresh token via the role's grant flow and stores it in
// the per-role cache, replacing any existing entry. Callers that need
// stampede protection must hold the per-role lock (LockForKey).
func (b *backend) mintAndCache(ctx context.Context, s logical.Storage, roleName string, cfg *salesforceConfig, role *salesforceRole) (*cachedToken, error) {
	now := time.Now()
	res, err := b.mintToken(ctx, cfg, role)
	if err != nil {
		return nil, err
	}

	ct := &cachedToken{
		AccessToken: res.AccessToken,
		InstanceURL: res.InstanceURL,
		TokenType:   res.TokenType,
		Scope:       res.Scope,
		IssuedAt:    now,
		ExpiresAt:   computeExpiry(now, role, res),
	}
	if err := b.putCachedToken(ctx, s, roleName, ct); err != nil {
		return nil, err
	}
	b.Logger().Debug("minted salesforce access token",
		"role", roleName, "grant_type", role.GrantType, "expires_at", ct.ExpiresAt)
	return ct, nil
}

// mintToken dispatches to the correct grant flow.
func (b *backend) mintToken(ctx context.Context, cfg *salesforceConfig, role *salesforceRole) (*tokenResult, error) {
	switch role.GrantType {
	case grantClientCredential:
		return requestClientCredentialsToken(ctx, cfg, role)
	case grantJWTBearer:
		return requestJWTBearerToken(ctx, cfg, role)
	default:
		return nil, fmt.Errorf("unsupported grant_type %q", role.GrantType)
	}
}

// computeExpiry derives the token expiry. Salesforce usually omits expires_in,
// so fall back to the role's configured token_ttl.
func computeExpiry(now time.Time, role *salesforceRole, res *tokenResult) time.Time {
	if res.ExpiresIn > 0 {
		return now.Add(time.Duration(res.ExpiresIn) * time.Second)
	}
	ttl := role.TokenTTL
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return now.Add(ttl)
}
