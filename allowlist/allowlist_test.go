package allowlist

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

var exampleConfig = &config{
	Format: "v1",
	Allowlist: []*AllowlistEntry{
		&AllowlistEntry{Domain: "example.com"},                                  // Can access any site
		&AllowlistEntry{Domain: "only-opgee.com", Sites: []string{"OPGEE"}},     // Can only access OPGEE
		&AllowlistEntry{Email: "test@only-pacta.com", Sites: []string{"PACTA"}}, // Only test@ can access PACTA
	},
}

func TestCheck(t *testing.T) {
	c, err := newChecker(exampleConfig)
	if err != nil {
		t.Fatalf("failed to init checker: %v", err)
	}

	tests := []struct {
		desc  string
		email string
		want  *Entity
	}{
		{
			desc:  "allowed on any site",
			email: "allowed@example.com",
			want:  &Entity{AllowAllSites: true},
		},
		{
			desc:  "domain not in the allowlist",
			email: "denied@example.net",
			want:  nil,
		},
		{
			desc:  "domain allowlisted for OPGEE",
			email: "any-email@only-opgee.com",
			want:  &Entity{AllowedSites: []Site{SiteOPGEE}},
		},
		{
			desc:  "email allowlisted for PACTA",
			email: "test@only-pacta.com",
			want:  &Entity{AllowedSites: []Site{SitePACTA}},
		},
		{
			desc:  "different email allowlisted for PACTA",
			email: "not-allowed@only-pacta.com",
			want:  nil,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			got, err := c.Check(test.email)
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("unexpected Check() results (-want +got)\n%s", diff)
			}
		})
	}
}

func TestCheck_Error(t *testing.T) {
	c, err := newChecker(exampleConfig)
	if err != nil {
		t.Fatalf("failed to init checker: %v", err)
	}

	entity, err := c.Check("malformed.biz")
	if err == nil {
		t.Fatal("Check returned no error for invalid email address")
	}
	if entity != nil {
		t.Errorf("Check said invalid email was allowed: %+v", entity)
	}
}
