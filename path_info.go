package salesforce

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathInfo exposes a read-only "info" endpoint so the empty backend is
// verifiably mounted and responsive before any business logic exists.
func pathInfo(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "info",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathInfoRead,
				},
			},
			HelpSynopsis:    "Report basic information about the Salesforce secrets engine.",
			HelpDescription: "Returns the plugin name and supported OAuth grant flows.",
		},
	}
}

func (b *backend) pathInfoRead(_ context.Context, _ *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return &logical.Response{
		Data: map[string]interface{}{
			"plugin": "vault-plugin-secrets-salesforce",
			"flows":  []string{"jwt_bearer", "client_credentials"},
		},
	}, nil
}
