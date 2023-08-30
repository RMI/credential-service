// Package allowlist provides basic capabilities for authorizing email addresses against a domain allowlist.
package allowlist

import (
	"fmt"
	"strings"
)

type Checker struct {
	allowedDomains map[string]bool
}

func NewChecker(allowedDomains []string) *Checker {
	m := make(map[string]bool)
	for _, ad := range allowedDomains {
		m[ad] = true
	}
	return &Checker{
		allowedDomains: m,
	}
}

// Check returns if the email is of an allowlisted domain, and errors if the
// email is incorrectly formatted. Subdomains are not handled specially, only
// exact matches are allowed.
func (c *Checker) Check(email string) (bool, error) {
	_, domain, ok := strings.Cut(email, "@")
	if !ok {
		return false, fmt.Errorf("email %q was missing '@'", email)
	}

	return c.allowedDomains[domain], nil
}
