// Copyright (c) 2026 DarthVaderRC.
// SPDX-License-Identifier: MPL-2.0

package salesforce

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathRotate(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name") + "/rotate",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role whose cached token to rotate.",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRotate},
			},
			HelpSynopsis: "Force a fresh Salesforce access token for a role.",
			HelpDescription: `
Discards the role's cached token and mints a new one immediately. Subsequent
reads of creds/<name> serve the new token. Previously issued tokens for this
role remain valid at Salesforce until they expire unless the role sets
revoke_tokens=true, in which case the engine calls Salesforce's /revoke for the
outgoing token (which, because the token is shared per role, affects all current
holders).
`,
		},
	}
}

func (b *backend) pathRotate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
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

	lock := locksutil.LockForKey(b.locks, roleName)
	lock.Lock()
	defer lock.Unlock()

	// If the role opts in, invalidate the outgoing token at Salesforce before
	// dropping it from the cache.
	b.revokeCachedTokenAtSalesforce(ctx, req.Storage, roleName, role)

	if err := b.deleteCachedToken(ctx, req.Storage, roleName); err != nil {
		return nil, err
	}
	ct, err := b.mintAndCache(ctx, req.Storage, roleName, cfg, role)
	if err != nil {
		return nil, err
	}
	b.Logger().Info("rotated salesforce token for role", "role", roleName, "expires_at", ct.ExpiresAt)
	return &logical.Response{
		Data: map[string]interface{}{
			"rotated":    true,
			"role":       roleName,
			"expires_at": ct.ExpiresAt.UTC().Format(time.RFC3339),
		},
	}, nil
}
