package salesforce

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// secretAccessTokenType is the Vault secret type for issued Salesforce tokens.
const secretAccessTokenType = "salesforce_access_token"

func secretAccessToken(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: secretAccessTokenType,
		Fields: map[string]*framework.FieldSchema{
			"access_token": {
				Type:        framework.TypeString,
				Description: "The Salesforce OAuth access token.",
			},
			"instance_url": {
				Type:        framework.TypeString,
				Description: "The Salesforce instance URL for subsequent API calls.",
			},
		},
		Revoke: b.secretAccessTokenRevoke,
		Renew:  b.secretAccessTokenRenew,
	}
}

// secretAccessTokenRevoke clears the role's cached token. Because the same
// Salesforce token is shared across all leases of a role, the default revoke
// behavior is cache-clear only (it does not call Salesforce /revoke, which
// would invalidate the token for every other holder).
func (b *backend) secretAccessTokenRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, nil
	}
	role, ok := roleRaw.(string)
	if !ok || role == "" {
		return nil, nil
	}
	if err := b.deleteCachedToken(ctx, req.Storage, role); err != nil {
		return nil, err
	}
	b.Logger().Debug("revoked lease; cleared cached salesforce token", "role", role)
	return nil, nil
}

// secretAccessTokenRenew extends the lease up to its max TTL while the
// underlying cached token is still fresh.
func (b *backend) secretAccessTokenRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, nil
	}
	roleName, _ := roleRaw.(string)

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	resp := &logical.Response{Secret: req.Secret}
	if role != nil {
		resp.Secret.TTL = role.TTL
		resp.Secret.MaxTTL = role.MaxTTL
	}
	return resp, nil
}
