package salesforce

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestInfo_Read(t *testing.T) {
	b, storage := testBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "info", Storage: storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("info read failed: err=%v resp=%v", err, resp)
	}
	if resp.Data["plugin"] != "vault-plugin-secrets-salesforce" {
		t.Errorf("plugin = %v", resp.Data["plugin"])
	}
	flows, ok := resp.Data["flows"].([]string)
	if !ok || len(flows) != 2 {
		t.Errorf("flows = %v, want jwt_bearer + client_credentials", resp.Data["flows"])
	}
}

func nameFieldData(name string) *framework.FieldData {
	return &framework.FieldData{
		Raw:    map[string]interface{}{"name": name},
		Schema: map[string]*framework.FieldSchema{"name": {Type: framework.TypeString}},
	}
}

func TestExistenceChecks(t *testing.T) {
	b, storage := testBackend(t)
	ctx := context.Background()
	req := &logical.Request{Storage: storage}

	mustCheck := func(fn func(context.Context, *logical.Request, *framework.FieldData) (bool, error), name string) bool {
		ok, err := fn(ctx, req, nameFieldData(name))
		if err != nil {
			t.Fatalf("existence check err: %v", err)
		}
		return ok
	}

	if mustCheck(b.pathConfigExistenceCheck, "nope") {
		t.Error("config existence should be false before creation")
	}
	if mustCheck(b.pathRoleExistenceCheck, "nope") {
		t.Error("role existence should be false before creation")
	}

	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation, Path: "config/acme", Storage: storage,
		Data: map[string]interface{}{"login_url": "https://x.my.salesforce.com", "client_id": "cid", "client_secret": "s"},
	}); err != nil {
		t.Fatalf("config write: %v", err)
	}
	if !mustCheck(b.pathConfigExistenceCheck, "acme") {
		t.Error("config existence should be true after creation")
	}
}
