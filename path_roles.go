// Copyright (c) 2026 DarthVaderRC.
// SPDX-License-Identifier: MPL-2.0

package salesforce

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const rolesStoragePrefix = "role/"

const (
	grantJWTBearer        = "jwt_bearer"
	grantClientCredential = "client_credentials"
)

// salesforceRole is a token-issuing role bound to a config and a grant flow.
type salesforceRole struct {
	Config           string        `json:"config"`
	GrantType        string        `json:"grant_type"`
	Username         string        `json:"username"`
	Scopes           []string      `json:"scopes"`
	TokenTTL         time.Duration `json:"token_ttl"`
	TTL              time.Duration `json:"ttl"`
	MaxTTL           time.Duration `json:"max_ttl"`
	RenewSkew        time.Duration `json:"renew_skew"`
	JWTExpiry        time.Duration `json:"jwt_expiry"`
	Audience         string        `json:"audience"`
	UseIntrospection bool          `json:"use_introspection"`
	RevokeTokens     bool          `json:"revoke_tokens"`
}

func pathRoles(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role.",
					Required:    true,
				},
				"config": {
					Type:        framework.TypeString,
					Description: "Name of the config/<name> this role uses.",
				},
				"grant_type": {
					Type:        framework.TypeString,
					Description: "OAuth grant flow: jwt_bearer or client_credentials.",
				},
				"username": {
					Type:        framework.TypeString,
					Description: "Salesforce username for the JWT 'sub' claim. Required for jwt_bearer.",
				},
				"scopes": {
					Type:        framework.TypeCommaStringSlice,
					Description: "OAuth scopes (forwarded for client_credentials).",
				},
				"token_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Assumed access-token lifetime; drives cache expiry. Default 15m.",
					Default:     900,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default Vault lease TTL for issued tokens.",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum Vault lease TTL for issued tokens.",
				},
				"renew_skew": {
					Type:        framework.TypeDurationSecond,
					Description: "Re-mint this long before token expiry. Default 60s.",
					Default:     60,
				},
				"jwt_expiry": {
					Type:        framework.TypeDurationSecond,
					Description: "JWT assertion 'exp' window. Default 3m, max 5m.",
					Default:     180,
				},
				"audience": {
					Type:        framework.TypeString,
					Description: "Override JWT 'aud'. Defaults to the config login_url.",
				},
				"use_introspection": {
					Type:        framework.TypeBool,
					Description: "Reserved; not yet implemented (no effect). Token expiry is derived from token_ttl. Default false.",
					Default:     false,
				},
				"revoke_tokens": {
					Type:        framework.TypeBool,
					Description: "If true, call the Salesforce /revoke endpoint when a lease is revoked or the role is rotated. Because one token is shared across all leases of a role, revoking one lease revokes the token for all current holders. Default false.",
					Default:     false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathRoleWrite},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathRoleRead},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.pathRoleDelete},
			},
			ExistenceCheck:  b.pathRoleExistenceCheck,
			HelpSynopsis:    "Manage Salesforce token-issuing roles.",
			HelpDescription: "Create, read, update, or delete a role that issues Salesforce OAuth access tokens via a given grant flow and identity.",
		},
		{
			Pattern: "roles/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathRoleList},
			},
			HelpSynopsis:    "List Salesforce roles.",
			HelpDescription: "List the names of all configured roles.",
		},
	}
}

func (b *backend) getRole(ctx context.Context, s logical.Storage, name string) (*salesforceRole, error) {
	entry, err := s.Get(ctx, rolesStoragePrefix+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	role := &salesforceRole{}
	if err := entry.DecodeJSON(role); err != nil {
		return nil, err
	}
	return role, nil
}

func (b *backend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := b.getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *backend) pathRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	role, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	existing := role != nil
	var old salesforceRole
	if existing {
		old = *role
	} else {
		role = &salesforceRole{}
	}

	if v, ok := data.GetOk("config"); ok {
		role.Config = v.(string)
	}
	if v, ok := data.GetOk("grant_type"); ok {
		role.GrantType = v.(string)
	}
	if v, ok := data.GetOk("username"); ok {
		role.Username = v.(string)
	}
	if v, ok := data.GetOk("scopes"); ok {
		role.Scopes = v.([]string)
	}
	if v, ok := data.GetOk("token_ttl"); ok {
		role.TokenTTL = time.Duration(v.(int)) * time.Second
	} else if role.TokenTTL == 0 {
		role.TokenTTL = time.Duration(data.Get("token_ttl").(int)) * time.Second
	}
	if v, ok := data.GetOk("ttl"); ok {
		role.TTL = time.Duration(v.(int)) * time.Second
	}
	if v, ok := data.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(v.(int)) * time.Second
	}
	if v, ok := data.GetOk("renew_skew"); ok {
		role.RenewSkew = time.Duration(v.(int)) * time.Second
	} else if role.RenewSkew == 0 {
		role.RenewSkew = time.Duration(data.Get("renew_skew").(int)) * time.Second
	}
	if v, ok := data.GetOk("jwt_expiry"); ok {
		role.JWTExpiry = time.Duration(v.(int)) * time.Second
	} else if role.JWTExpiry == 0 {
		role.JWTExpiry = time.Duration(data.Get("jwt_expiry").(int)) * time.Second
	}
	if v, ok := data.GetOk("audience"); ok {
		role.Audience = v.(string)
	}
	if v, ok := data.GetOk("use_introspection"); ok {
		role.UseIntrospection = v.(bool)
	}
	if v, ok := data.GetOk("revoke_tokens"); ok {
		role.RevokeTokens = v.(bool)
	}

	// The Salesforce identity (username -> JWT sub) and the bound config define
	// the role's security identity. Allowing them to be repointed on update lets
	// an update-only principal impersonate a different Salesforce user or cross
	// to another tenant's config. Treat them as immutable; require delete+recreate.
	if existing {
		if role.Username != old.Username {
			return logical.ErrorResponse("username is immutable; delete and recreate the role to change the Salesforce identity"), nil
		}
		if role.Config != old.Config {
			return logical.ErrorResponse("config is immutable; delete and recreate the role to bind a different config"), nil
		}
	}

	if errResp := b.validateRole(ctx, req.Storage, role); errResp != nil {
		return errResp, nil
	}

	entry, err := logical.StorageEntryJSON(rolesStoragePrefix+name, role)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	// A role change can alter token parameters; drop the cached token so the next
	// read re-mints under the updated role.
	if err := b.deleteCachedToken(ctx, req.Storage, name); err != nil {
		return nil, err
	}

	if role.UseIntrospection {
		resp := &logical.Response{}
		resp.AddWarning("use_introspection is reserved and currently has no effect; token expiry is derived from token_ttl")
		return resp, nil
	}
	return nil, nil
}

// validateRole enforces grant-flow invariants and the bound config's required
// secret material. Returns an error response (not a Go error) for user mistakes.
func (b *backend) validateRole(ctx context.Context, s logical.Storage, role *salesforceRole) *logical.Response {
	if role.Config == "" {
		return logical.ErrorResponse("config is required")
	}
	if role.GrantType != grantJWTBearer && role.GrantType != grantClientCredential {
		return logical.ErrorResponse("grant_type must be %q or %q", grantJWTBearer, grantClientCredential)
	}
	if role.MaxTTL > 0 && role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl (%s) must not exceed max_ttl (%s)", role.TTL, role.MaxTTL)
	}
	if role.JWTExpiry > 5*time.Minute {
		return logical.ErrorResponse("jwt_expiry (%s) must not exceed 5m (Salesforce rejects assertions further in the future)", role.JWTExpiry)
	}
	if role.RenewSkew < 0 {
		return logical.ErrorResponse("renew_skew (%s) must not be negative", role.RenewSkew)
	}
	if role.TokenTTL > 0 && role.RenewSkew >= role.TokenTTL {
		return logical.ErrorResponse("renew_skew (%s) must be less than token_ttl (%s)", role.RenewSkew, role.TokenTTL)
	}

	cfg, err := b.getConfig(ctx, s, role.Config)
	if err != nil {
		return logical.ErrorResponse("error loading config %q: %s", role.Config, err)
	}
	if cfg == nil {
		return logical.ErrorResponse("config %q does not exist", role.Config)
	}

	switch role.GrantType {
	case grantJWTBearer:
		if role.Username == "" {
			return logical.ErrorResponse("username is required for the jwt_bearer grant")
		}
		if cfg.PrivateKey == "" {
			return logical.ErrorResponse("config %q has no private_key, required for the jwt_bearer grant", role.Config)
		}
	case grantClientCredential:
		if cfg.ClientSecret == "" {
			return logical.ErrorResponse("config %q has no client_secret, required for the client_credentials grant", role.Config)
		}
	}
	return nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role, err := b.getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	return &logical.Response{Data: map[string]interface{}{
		"config":            role.Config,
		"grant_type":        role.GrantType,
		"username":          role.Username,
		"scopes":            role.Scopes,
		"token_ttl":         int64(role.TokenTTL.Seconds()),
		"ttl":               int64(role.TTL.Seconds()),
		"max_ttl":           int64(role.MaxTTL.Seconds()),
		"renew_skew":        int64(role.RenewSkew.Seconds()),
		"jwt_expiry":        int64(role.JWTExpiry.Seconds()),
		"audience":          role.Audience,
		"use_introspection": role.UseIntrospection,
		"revoke_tokens":     role.RevokeTokens,
	}}, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if err := b.deleteCachedToken(ctx, req.Storage, name); err != nil {
		return nil, err
	}
	if err := req.Storage.Delete(ctx, rolesStoragePrefix+name); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, rolesStoragePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}
