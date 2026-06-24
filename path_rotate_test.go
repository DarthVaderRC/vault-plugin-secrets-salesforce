package salesforce

import (
	"context"
	"testing"

	"github.com/DarthVaderRC/vault-plugin-secrets-salesforce/internal/sftest"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestRotate_ForcesFreshToken(t *testing.T) {
	m := sftest.New()
	defer m.Close()
	b, storage := setupCC(t, m, "15m")
	ctx := context.Background()

	// Prime the cache.
	first := readCreds(t, b, storage)
	firstToken := first.Data["access_token"].(string)

	// Rotate.
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/cc/rotate", Storage: storage,
	})
	if err != nil || resp == nil || resp.IsError() {
		t.Fatalf("rotate failed: err=%v resp=%v", err, resp)
	}
	if resp.Data["rotated"] != true {
		t.Errorf("rotated = %v, want true", resp.Data["rotated"])
	}
	if m.MintCount() != 2 {
		t.Errorf("expected a fresh mint on rotate, got MintCount=%d", m.MintCount())
	}

	// Next read serves the new token from cache (no extra mint).
	second := readCreds(t, b, storage)
	if second.Data["cached"] != true {
		t.Errorf("read after rotate should be cached, got cached=%v", second.Data["cached"])
	}
	if second.Data["access_token"] == firstToken {
		t.Errorf("token did not change after rotate: %v", firstToken)
	}
	if m.MintCount() != 2 {
		t.Errorf("read after rotate should not mint again, got MintCount=%d", m.MintCount())
	}
}

func TestRotate_UnknownRole(t *testing.T) {
	b, storage := testBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation, Path: "roles/missing/rotate", Storage: storage,
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Errorf("expected error for unknown role, got %v", resp)
	}
}
