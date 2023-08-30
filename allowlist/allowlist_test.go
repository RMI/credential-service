package allowlist

import "testing"

func TestCheck(t *testing.T) {
	allowedDomain := "example.com"

	c := NewChecker([]string{allowedDomain})

	allowed, err := c.Check("allowed@example.com")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !allowed {
		t.Error("Check said email was not allowed, expected allowed")
	}

	allowed, err = c.Check("denied@example.net")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if allowed {
		t.Error("Check said email was allowed, expected not allowed")
	}

	allowed, err = c.Check("malformed.biz")
	if err == nil {
		t.Fatal("Check returned no error for invalid email address")
	}
	if allowed {
		t.Error("Check said invalid email was allowed")
	}
}
