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
