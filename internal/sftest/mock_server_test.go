// Copyright (c) 2026 DarthVaderRC.
// SPDX-License-Identifier: MPL-2.0

package sftest

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func postForm(tokenURL string, values url.Values) (string, error) {
	resp, err := http.PostForm(tokenURL, values)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

func TestMockServer_Success(t *testing.T) {
	m := New()
	defer m.Close()

	resp, err := postForm(m.TokenURL(), url.Values{"grant_type": {"client_credentials"}})
	if err != nil {
		t.Fatalf("post failed: %v", err)
	}
	if !strings.Contains(resp, "access_token") || !strings.Contains(resp, "mint1") {
		t.Errorf("unexpected response: %s", resp)
	}
	if m.MintCount() != 1 {
		t.Errorf("MintCount = %d, want 1", m.MintCount())
	}
	if len(m.Requests()) != 1 || m.Requests()[0]["grant_type"] != "client_credentials" {
		t.Errorf("requests not recorded correctly: %v", m.Requests())
	}
}

func TestMockServer_FailMode(t *testing.T) {
	m := New()
	defer m.Close()
	m.SetFailMode("invalid_client")

	resp, err := postForm(m.TokenURL(), url.Values{"grant_type": {"client_credentials"}})
	if err != nil {
		t.Fatalf("post failed: %v", err)
	}
	if !strings.Contains(resp, "invalid_client") {
		t.Errorf("expected invalid_client error, got: %s", resp)
	}
}

func TestMockServer_UniqueMints(t *testing.T) {
	m := New()
	defer m.Close()
	r1, _ := postForm(m.TokenURL(), url.Values{"grant_type": {"client_credentials"}})
	r2, _ := postForm(m.TokenURL(), url.Values{"grant_type": {"client_credentials"}})
	if r1 == r2 {
		t.Errorf("expected distinct tokens across mints, both = %s", r1)
	}
}
