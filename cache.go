// Copyright (c) 2026 DarthVaderRC.
// SPDX-License-Identifier: MPL-2.0

package salesforce

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

const cacheStoragePrefix = "cache/"

// cachedToken is a per-role cached access token stored in the barrier.
type cachedToken struct {
	AccessToken string    `json:"access_token"`
	InstanceURL string    `json:"instance_url"`
	TokenType   string    `json:"token_type"`
	Scope       string    `json:"scope"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// fresh reports whether the token is still usable given the renew skew, i.e.
// now < expiresAt - skew.
func (c *cachedToken) fresh(now time.Time, skew time.Duration) bool {
	return now.Before(c.ExpiresAt.Add(-skew))
}

func (b *backend) getCachedToken(ctx context.Context, s logical.Storage, role string) (*cachedToken, error) {
	entry, err := s.Get(ctx, cacheStoragePrefix+role)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	ct := &cachedToken{}
	if err := entry.DecodeJSON(ct); err != nil {
		return nil, err
	}
	return ct, nil
}

func (b *backend) putCachedToken(ctx context.Context, s logical.Storage, role string, ct *cachedToken) error {
	entry, err := logical.StorageEntryJSON(cacheStoragePrefix+role, ct)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func (b *backend) deleteCachedToken(ctx context.Context, s logical.Storage, role string) error {
	return s.Delete(ctx, cacheStoragePrefix+role)
}

// deleteCachedTokensForConfig clears cached tokens for every role bound to the
// named config. Used when a config changes (credentials rotated, endpoint
// repointed) so a stale token minted under the old config is never served.
func (b *backend) deleteCachedTokensForConfig(ctx context.Context, s logical.Storage, configName string) error {
	names, err := s.List(ctx, rolesStoragePrefix)
	if err != nil {
		return err
	}
	for _, name := range names {
		role, err := b.getRole(ctx, s, name)
		if err != nil {
			return err
		}
		if role != nil && role.Config == configName {
			if err := b.deleteCachedToken(ctx, s, name); err != nil {
				return err
			}
		}
	}
	return nil
}

// revokeCachedTokenAtSalesforce calls the Salesforce /revoke endpoint for the
// role's currently cached token when the role opts in via revoke_tokens. Because
// the token is shared across all leases of the role, this invalidates it for
// every current holder. Errors are logged and swallowed so a lease revoke or
// rotate is never blocked by a transient Salesforce failure.
func (b *backend) revokeCachedTokenAtSalesforce(ctx context.Context, s logical.Storage, roleName string, role *salesforceRole) {
	if role == nil || !role.RevokeTokens {
		return
	}
	ct, err := b.getCachedToken(ctx, s, roleName)
	if err != nil || ct == nil || ct.AccessToken == "" {
		return
	}
	cfg, err := b.getConfig(ctx, s, role.Config)
	if err != nil || cfg == nil {
		return
	}
	if err := revokeToken(ctx, cfg, ct.AccessToken); err != nil {
		b.Logger().Warn("salesforce token revoke failed", "role", roleName, "error", err.Error())
		return
	}
	b.Logger().Info("revoked salesforce token at salesforce", "role", roleName)
}
