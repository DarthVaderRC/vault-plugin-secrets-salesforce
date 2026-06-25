// Copyright (c) 2026 DarthVaderRC.
// SPDX-License-Identifier: MPL-2.0

package salesforce

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configStoragePrefix = "config/"
	redactedValue       = "<redacted>"
)

// salesforceConfig is the stored connection configuration for one Salesforce
// org/app. Secret fields (ClientSecret, PrivateKey) live only in the barrier and
// are never returned by read operations.
type salesforceConfig struct {
	LoginURL               string `json:"login_url"`
	TokenURL               string `json:"token_url"`
	ClientID               string `json:"client_id"`
	ClientSecret           string `json:"client_secret"`
	PrivateKey             string `json:"private_key"`
	CACert                 string `json:"ca_cert"`
	TLSSkipVerify          bool   `json:"tls_skip_verify"`
	AllowNonSalesforceHost bool   `json:"allow_non_salesforce_host"`
}

// tokenURL returns the effective token endpoint, defaulting to
// "<login_url>/services/oauth2/token" when TokenURL is not set.
func (c *salesforceConfig) tokenURL() string {
	if c.TokenURL != "" {
		return c.TokenURL
	}
	return strings.TrimRight(c.LoginURL, "/") + "/services/oauth2/token"
}

func pathConfig(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of this Salesforce org/app configuration.",
					Required:    true,
				},
				"login_url": {
					Type:        framework.TypeString,
					Description: "Base login host, e.g. https://login.salesforce.com, https://test.salesforce.com, or https://<MyDomain>.my.salesforce.com.",
				},
				"token_url": {
					Type:        framework.TypeString,
					Description: "Optional override for the full token endpoint. Defaults to <login_url>/services/oauth2/token.",
				},
				"client_id": {
					Type:        framework.TypeString,
					Description: "Connected App / External Client App Consumer Key (OAuth client_id).",
				},
				"client_secret": {
					Type:        framework.TypeString,
					Description: "Consumer Secret. Required for client_credentials roles. Write-only; never returned.",
				},
				"private_key": {
					Type:        framework.TypeString,
					Description: "PEM RSA private key for JWT Bearer signing. Required for jwt_bearer roles. Write-only; never returned.",
				},
				"ca_cert": {
					Type:        framework.TypeString,
					Description: "Optional PEM CA bundle used to validate the Salesforce TLS endpoint.",
				},
				"tls_skip_verify": {
					Type:        framework.TypeBool,
					Description: "Disable TLS verification (sandbox/testing only). Defaults to false.",
					Default:     false,
				},
				"allow_non_salesforce_host": {
					Type:        framework.TypeBool,
					Description: "Allow the token endpoint to target a non-Salesforce host (e.g. a private gateway). Defaults to false, which restricts the host to *.salesforce.com / *.force.com (loopback is always allowed for testing).",
					Default:     false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.pathConfigWrite},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.pathConfigRead},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.pathConfigDelete},
			},
			ExistenceCheck:  b.pathConfigExistenceCheck,
			HelpSynopsis:    "Configure a Salesforce org/app connection.",
			HelpDescription: "Create, read, update, or delete the connection configuration (login URL, client ID, and secret material) for a Salesforce org/app.",
		},
		{
			Pattern: "config/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.pathConfigList},
			},
			HelpSynopsis:    "List Salesforce configurations.",
			HelpDescription: "List the names of all configured Salesforce org/app connections.",
		},
	}
}

func (b *backend) getConfig(ctx context.Context, s logical.Storage, name string) (*salesforceConfig, error) {
	entry, err := s.Get(ctx, configStoragePrefix+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	cfg := &salesforceConfig{}
	if err := entry.DecodeJSON(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (b *backend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	cfg, err := b.getConfig(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return cfg != nil, nil
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing configuration name"), nil
	}

	cfg, err := b.getConfig(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = &salesforceConfig{}
	}

	if v, ok := data.GetOk("login_url"); ok {
		cfg.LoginURL = v.(string)
	}
	if v, ok := data.GetOk("token_url"); ok {
		cfg.TokenURL = v.(string)
	}
	if v, ok := data.GetOk("client_id"); ok {
		cfg.ClientID = v.(string)
	}
	if v, ok := data.GetOk("client_secret"); ok {
		cfg.ClientSecret = v.(string)
	}
	if v, ok := data.GetOk("private_key"); ok {
		cfg.PrivateKey = v.(string)
	}
	if v, ok := data.GetOk("ca_cert"); ok {
		cfg.CACert = v.(string)
	}
	if v, ok := data.GetOk("tls_skip_verify"); ok {
		cfg.TLSSkipVerify = v.(bool)
	}
	if v, ok := data.GetOk("allow_non_salesforce_host"); ok {
		cfg.AllowNonSalesforceHost = v.(bool)
	}

	if cfg.LoginURL == "" {
		return logical.ErrorResponse("login_url is required"), nil
	}
	if cfg.ClientID == "" {
		return logical.ErrorResponse("client_id is required"), nil
	}
	if err := validateTokenHost(cfg.tokenURL(), cfg.AllowNonSalesforceHost); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	entry, err := logical.StorageEntryJSON(configStoragePrefix+name, cfg)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	cfg, err := b.getConfig(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	return &logical.Response{Data: cfg.redactedMap()}, nil
}

// redactedMap returns the config as a response map with secret fields redacted.
func (c *salesforceConfig) redactedMap() map[string]interface{} {
	m := map[string]interface{}{
		"login_url":                 c.LoginURL,
		"token_url":                 c.tokenURL(),
		"client_id":                 c.ClientID,
		"ca_cert":                   c.CACert,
		"tls_skip_verify":           c.TLSSkipVerify,
		"allow_non_salesforce_host": c.AllowNonSalesforceHost,
	}
	if c.ClientSecret != "" {
		m["client_secret"] = redactedValue
	} else {
		m["client_secret"] = ""
	}
	if c.PrivateKey != "" {
		m["private_key"] = redactedValue
	} else {
		m["private_key"] = ""
	}
	return m
}

func (b *backend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if err := req.Storage.Delete(ctx, configStoragePrefix+name); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathConfigList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, configStoragePrefix)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(names), nil
}
