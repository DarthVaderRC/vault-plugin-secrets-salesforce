package salesforce

import (
	"testing"
	"time"
)

func TestCachedToken_Fresh_Boundaries(t *testing.T) {
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	skew := time.Minute

	cases := []struct {
		name      string
		expiresAt time.Time
		now       time.Time
		want      bool
	}{
		{"well before expiry", base.Add(10 * time.Minute), base, true},
		{"just inside skew window (stale)", base.Add(30 * time.Second), base, false},
		{"exactly at skew boundary (stale)", base.Add(skew), base, false},
		{"one ns before skew boundary (fresh)", base.Add(skew + 1), base, true},
		{"already expired", base.Add(-time.Second), base, false},
		{"expires exactly now (stale)", base, base, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ct := &cachedToken{ExpiresAt: tc.expiresAt}
			if got := ct.fresh(tc.now, skew); got != tc.want {
				t.Errorf("fresh(now=%v, skew=%v) with expiresAt=%v = %v, want %v",
					tc.now, skew, tc.expiresAt, got, tc.want)
			}
		})
	}
}

func TestComputeExpiry(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name     string
		tokenTTL time.Duration
		expireIn int
		want     time.Time
	}{
		{"uses expires_in when present", 15 * time.Minute, 3600, now.Add(time.Hour)},
		{"falls back to token_ttl when expires_in absent", 20 * time.Minute, 0, now.Add(20 * time.Minute)},
		{"defaults to 15m when neither set", 0, 0, now.Add(15 * time.Minute)},
		{"expires_in takes precedence over token_ttl", 5 * time.Minute, 600, now.Add(10 * time.Minute)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			role := &salesforceRole{TokenTTL: tc.tokenTTL}
			res := &tokenResult{ExpiresIn: tc.expireIn}
			if got := computeExpiry(now, role, res); !got.Equal(tc.want) {
				t.Errorf("computeExpiry = %v, want %v", got, tc.want)
			}
		})
	}
}
