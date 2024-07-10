// Package allowlist provides basic capabilities for authorizing email addresses against a domain allowlist.
package allowlist

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

type config struct {
	Format    string            `json:"format"`
	Allowlist []*AllowlistEntry `json:"allowlist"`
}

// AllowlistEntry maps some entity (a domain or email) to a list of authorized sites.
type AllowlistEntry struct {
	// Only one of Domain or Email may be set
	Domain string `json:"domain"`
	Email  string `json:"email"`

	// If empty, all sites are allowed.
	// This isn't a "fail closed" default, but I think that's fine at this stage.
	Sites []string `json:"sites"`
}

type Site string

const (
	SiteOPGEE = Site("OPGEE")
	SitePACTA = Site("PACTA")
)

type Entity struct {
	// If true, AllowedSites is ignored
	AllowAllSites bool
	AllowedSites  []Site
}

type Checker struct {
	allowedDomains map[string]*Entity
	allowedEmails  map[string]*Entity
}

func NewCheckerFromConfigFile(fn string) (*Checker, error) {
	f, err := os.Open(fn)
	if err != nil {
		return nil, fmt.Errorf("failed to open allowlist config file: %w", err)
	}
	defer f.Close()

	var cfg config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to decode allowlist config: %w", err)
	}

	return newChecker(&cfg)
}

func newChecker(cfg *config) (*Checker, error) {
	switch cfg.Format {
	case "v1":
		// Valid, continue
	case "":
		return nil, errors.New("config file had no 'format' field, which is required")
	default:
		return nil, fmt.Errorf("unknown format %q", cfg.Format)
	}

	allowedDomains := make(map[string]*Entity)
	allowedEmails := make(map[string]*Entity)
	for i, ae := range cfg.Allowlist {
		if ae.Domain != "" && ae.Email != "" {
			return nil, fmt.Errorf("allowlist entry specified both a domain (%q) and an email (%q), which isn't allowed", ae.Domain, ae.Email)
		}
		if ae.Domain == "" && ae.Email == "" {
			return nil, fmt.Errorf("allowlist entry at index %d did not specify a domain or email", i)
		}
		entity, err := parseEntity(ae.Sites)
		if err != nil {
			return nil, fmt.Errorf("failed to parse sites for entry at index %d: %w", i, err)
		}
		if ae.Domain != "" {
			allowedDomains[strings.ToLower(ae.Domain)] = entity
		}
		if ae.Email != "" {
			allowedEmails[strings.ToLower(ae.Email)] = entity
		}
	}
	return &Checker{
		allowedDomains: allowedDomains,
		allowedEmails:  allowedEmails,
	}, nil
}

func parseEntity(inp []string) (*Entity, error) {
	if len(inp) == 0 {
		return &Entity{AllowAllSites: true}, nil
	}
	var sites []Site
	for _, s := range inp {
		st, err := parseSite(s)
		if err != nil {
			return nil, fmt.Errorf("failed to parse entity %q: %w", s, err)
		}
		sites = append(sites, st)
	}
	return &Entity{AllowedSites: sites}, nil
}

func parseSite(inp string) (Site, error) {
	switch inp {
	case "OPGEE":
		return SiteOPGEE, nil
	case "PACTA":
		return SitePACTA, nil
	default:
		return "", errors.New("unknown site")
	}
}

// Check returns if the email is of an allowlisted domain, and errors if the
// email is incorrectly formatted. Subdomains are not handled specially, only
// exact matches are allowed.
func (c *Checker) Check(email string) (*Entity, error) {
	email = strings.ToLower(email)

	// First, check the email
	if tmp, ok := c.allowedEmails[email]; ok {
		return tmp, nil
	}

	_, domain, ok := strings.Cut(email, "@")
	if !ok {
		return nil, fmt.Errorf("email %q was missing '@'", email)
	}

	if tmp, ok := c.allowedDomains[domain]; ok {
		return tmp, nil
	}

	return nil, nil
}
