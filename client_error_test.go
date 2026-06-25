// Copyright (c) 2026 DarthVaderRC.
// SPDX-License-Identifier: MPL-2.0

package salesforce

import (
	"strings"
	"testing"
)

func TestParseTokenError_Matrix(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		body        string
		wantCode    string
		wantDescSub string
	}{
		{
			name:        "standard oauth error",
			status:      400,
			body:        `{"error":"invalid_grant","error_description":"user hasn't approved this consumer"}`,
			wantCode:    "invalid_grant",
			wantDescSub: "hasn't approved",
		},
		{
			name:        "invalid_client",
			status:      400,
			body:        `{"error":"invalid_client","error_description":"invalid client credentials"}`,
			wantCode:    "invalid_client",
			wantDescSub: "invalid client credentials",
		},
		{
			name:        "scope rejected",
			status:      400,
			body:        `{"error":"invalid_request","error_description":"scope parameter not supported"}`,
			wantCode:    "invalid_request",
			wantDescSub: "scope parameter not supported",
		},
		{
			name:     "non-JSON body (e.g. 503 HTML)",
			status:   503,
			body:     `<html>Service Unavailable</html>`,
			wantCode: "", // no parseable code
		},
		{
			name:     "empty body",
			status:   500,
			body:     ``,
			wantCode: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := parseTokenError(tc.status, []byte(tc.body))
			sfErr, ok := err.(*salesforceError)
			if !ok {
				t.Fatalf("error type = %T, want *salesforceError", err)
			}
			if sfErr.StatusCode != tc.status {
				t.Errorf("StatusCode = %d, want %d", sfErr.StatusCode, tc.status)
			}
			if sfErr.Code != tc.wantCode {
				t.Errorf("Code = %q, want %q", sfErr.Code, tc.wantCode)
			}
			// Error() string must include the status, and the code when present.
			msg := sfErr.Error()
			if !strings.Contains(msg, "400") && !strings.Contains(msg, "500") && !strings.Contains(msg, "503") {
				t.Errorf("Error() = %q, expected it to include the HTTP status", msg)
			}
			if tc.wantCode != "" && !strings.Contains(msg, tc.wantCode) {
				t.Errorf("Error() = %q, expected it to include code %q", msg, tc.wantCode)
			}
			if tc.wantDescSub != "" && !strings.Contains(msg, tc.wantDescSub) {
				t.Errorf("Error() = %q, expected it to include %q", msg, tc.wantDescSub)
			}
		})
	}
}

func TestIsRetryableStatus(t *testing.T) {
	cases := map[int]bool{
		200: false,
		400: false,
		401: false,
		403: false,
		404: false,
		429: true,
		500: true,
		502: true,
		503: true,
		504: true,
	}
	for status, want := range cases {
		if got := isRetryableStatus(status); got != want {
			t.Errorf("isRetryableStatus(%d) = %v, want %v", status, got, want)
		}
	}
}
