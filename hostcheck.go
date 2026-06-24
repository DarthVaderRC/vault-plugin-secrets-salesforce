package salesforce

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// salesforceHostSuffixes are the DNS suffixes the token endpoint is allowed to
// use by default. This is defense-in-depth: it prevents a misconfiguration (or
// a malicious config write) from sending OAuth client secrets / JWT assertions
// to a non-Salesforce host. Operators with a private gateway can opt out with
// allow_non_salesforce_host=true.
var salesforceHostSuffixes = []string{
	".salesforce.com",
	".force.com",
	".salesforce.mil", // Government Cloud
}

// validateTokenHost checks that the effective token endpoint uses https (except
// for loopback test servers) and targets an allowed Salesforce domain unless
// the operator has explicitly opted out.
func validateTokenHost(rawURL string, allowNonSalesforce bool) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid token endpoint URL: %w", err)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return fmt.Errorf("token endpoint URL %q has no host", rawURL)
	}

	loopback := isLoopbackHost(host)

	if u.Scheme != "https" && !loopback {
		return fmt.Errorf("token endpoint must use https, got scheme %q", u.Scheme)
	}

	if allowNonSalesforce || loopback {
		return nil
	}

	for _, suffix := range salesforceHostSuffixes {
		if strings.HasSuffix(host, suffix) {
			return nil
		}
	}
	return fmt.Errorf("token endpoint host %q is not an allowed Salesforce domain (allowed suffixes: %s); set allow_non_salesforce_host=true to override",
		host, strings.Join(salesforceHostSuffixes, ", "))
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
