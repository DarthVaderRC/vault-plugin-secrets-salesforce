// Copyright (c) 2026 DarthVaderRC.
// SPDX-License-Identifier: MPL-2.0

// Package sftest provides a mock Salesforce OAuth token endpoint for tests.
package sftest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"
)

// TokenResponse mirrors the subset of the Salesforce token response the engine
// consumes. Note that Salesforce typically omits expires_in.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	InstanceURL string `json:"instance_url"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope,omitempty"`
	ExpiresIn   int    `json:"expires_in,omitempty"`
}

// MockServer is an httptest-backed fake Salesforce token endpoint.
type MockServer struct {
	Server *httptest.Server

	mu sync.Mutex
	// requests records each received token request's form values.
	requests []map[string]string
	// failMode, when set, makes /services/oauth2/token return an OAuth error.
	failMode string
	// tokenBase plus a counter makes each mint observably unique so caching
	// tests can detect re-mints.
	tokenBase   string
	mintCounter int
	instanceURL string
	// assertionValidator, if set, validates the JWT assertion (jwt_bearer).
	assertionValidator func(assertion string) error
	// mintDelay, if set, makes each token request sleep before issuing, to
	// widen the race window in concurrency/anti-stampede tests.
	mintDelay time.Duration
	// transientFails, when > 0, makes the next N token requests return HTTP 503
	// (decremented per request) before succeeding — used for retry tests.
	transientFails int
	transientCode  int
}

// New returns a started MockServer. Call Close when done.
func New() *MockServer {
	m := &MockServer{
		tokenBase: "00Dxx0000000000",
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/services/oauth2/token", m.handleToken)
	m.Server = httptest.NewServer(mux)
	m.instanceURL = m.Server.URL // point instance_url at the mock so API calls can hit it too
	return m
}

// URL returns the base URL of the mock server (use as login_url/token_url base).
func (m *MockServer) URL() string { return m.Server.URL }

// TokenURL returns the full token endpoint URL.
func (m *MockServer) TokenURL() string { return m.Server.URL + "/services/oauth2/token" }

// Close shuts the server down.
func (m *MockServer) Close() { m.Server.Close() }

// SetFailMode makes the token endpoint return the given OAuth error
// ("invalid_grant", "invalid_client") or "server_error" for HTTP 500. Empty
// string restores success.
func (m *MockServer) SetFailMode(mode string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failMode = mode
}

// SetAssertionValidator installs a validator for the jwt_bearer assertion.
func (m *MockServer) SetAssertionValidator(fn func(assertion string) error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.assertionValidator = fn
}

// Requests returns a copy of all recorded token requests.
func (m *MockServer) Requests() []map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]map[string]string, len(m.requests))
	copy(out, m.requests)
	return out
}

// MintCount returns how many successful tokens have been issued.
func (m *MockServer) MintCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mintCounter
}

// SetMintDelay makes each token request sleep for d before issuing a token,
// widening the race window for concurrency tests.
func (m *MockServer) SetMintDelay(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mintDelay = d
}

// SetTransientFailures makes the next n token requests return the given HTTP
// status (e.g. 503 or 429) before succeeding, for exercising retry/backoff.
func (m *MockServer) SetTransientFailures(n, status int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.transientFails = n
	m.transientCode = status
}

func (m *MockServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	form := map[string]string{}
	for k := range r.Form {
		form[k] = r.Form.Get(k)
	}

	m.mu.Lock()
	m.requests = append(m.requests, form)
	failMode := m.failMode
	validator := m.assertionValidator
	mintDelay := m.mintDelay
	transient := 0
	if m.transientFails > 0 {
		m.transientFails--
		transient = m.transientCode
		if transient == 0 {
			transient = http.StatusServiceUnavailable
		}
	}
	m.mu.Unlock()

	if transient != 0 {
		http.Error(w, "transient failure", transient)
		return
	}

	switch failMode {
	case "":
		// success path below
	case "server_error":
		http.Error(w, "boom", http.StatusInternalServerError)
		return
	default:
		writeOAuthError(w, http.StatusBadRequest, failMode, "mock failure: "+failMode)
		return
	}

	if form["grant_type"] == "urn:ietf:params:oauth:grant-type:jwt-bearer" && validator != nil {
		if err := validator(form["assertion"]); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
			return
		}
	}

	if mintDelay > 0 {
		time.Sleep(mintDelay)
	}

	m.mu.Lock()
	m.mintCounter++
	token := fmt.Sprintf("%s!mint%d", m.tokenBase, m.mintCounter)
	instanceURL := m.instanceURL
	m.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(TokenResponse{
		AccessToken: token,
		InstanceURL: instanceURL,
		TokenType:   "Bearer",
		Scope:       form["scope"],
	})
}

func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": desc,
	})
}
