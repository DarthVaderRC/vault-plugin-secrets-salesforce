// Package salesforce implements a HashiCorp Vault secrets engine that brokers
// Salesforce OAuth 2.0 access tokens using the JWT Bearer and Client Credentials
// grant flows.
package salesforce

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/locksutil"
	"github.com/hashicorp/vault/sdk/logical"
)

// backend is the Salesforce secrets engine backend.
type backend struct {
	*framework.Backend

	// locks is a fixed pool of per-key locks used to serialize token minting
	// for a given role, preventing a stampede of concurrent mints on a cold or
	// expired cache.
	locks []*locksutil.LockEntry
}

// Factory returns a configured Salesforce secrets backend. Vault calls this when
// the plugin is mounted.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func newBackend() *backend {
	b := &backend{
		locks: locksutil.CreateLocks(),
	}
	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		Paths: framework.PathAppend(
			pathInfo(b),
			pathConfig(b),
			pathRoles(b),
			pathCreds(b),
		),
		Secrets: []*framework.Secret{
			secretAccessToken(b),
		},
	}
	return b
}

const backendHelp = `
The Salesforce secrets engine brokers Salesforce OAuth 2.0 access tokens.

Configure one or more Salesforce orgs/apps under config/<name>, define
token-issuing roles under roles/<name>, and read short-lived access tokens
from creds/<name>. Supported grant flows: JWT Bearer and Client Credentials.
`
