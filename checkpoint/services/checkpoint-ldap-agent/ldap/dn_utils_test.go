package ldapagent

import (
	"testing"
)

func TestValidateDN(t *testing.T) {
	tests := []struct {
		name  string
		dn    string
		valid bool
	}{
		// Valid DNs
		{"valid user dn", "uid=alice@example.com,ou=users,dc=test,dc=app", true},
		{"valid group dn", "cn=admins,ou=groups,dc=test,dc=app", true},
		{"lowercase and alphanumeric", "uid=user123,ou=users,dc=test,dc=app", true},
		{"dn with spaces", "cn=Test User,ou=users,dc=test,dc=app", true},
		{"dn with hyphens", "cn=test-user,ou=users,dc=test,dc=app", true},
		{"dn with dots", "cn=test.user,ou=users,dc=test,dc=app", true},
		{"dn with underscore", "uid=test_user,ou=users,dc=test,dc=app", true},
		{"empty dc", "uid=user,dc=", true}, // Syntactically valid, semantically questionable

		// Invalid DNs - injection attacks
		{"null byte injection", "uid=test\x00evil,ou=users,dc=test", false},
		{"cr injection", "uid=test\revil,ou=users,dc=test", false},
		{"lf injection", "uid=test\nevil,ou=users,dc=test", false},
		{"crlf injection", "uid=test\r\nevil,ou=users,dc=test", false},
		{"semicolon injection", "uid=test;DROP,ou=users,dc=test", false},
		{"angle bracket open", "uid=test<evil,ou=users,dc=test", false},
		{"angle bracket close", "uid=test>evil,ou=users,dc=test", false},

		// Invalid DNs - length
		{"exceeds max length", string(make([]byte, 513)), false},
		{"exactly max length", string(make([]byte, 512)), true},
		{"just under max length", string(make([]byte, 511)), true},

		// Invalid DNs - empty
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateDN(tt.dn)
			if got != tt.valid {
				t.Errorf("ValidateDN(%q) = %v, want %v", tt.dn, got, tt.valid)
			}
		})
	}
}

func TestValidateLDAPFilter(t *testing.T) {
	tests := []struct {
		name  string
		filter string
		valid bool
	}{
		// Valid filters
		{"simple equality", "(uid=alice)", true},
		{"equality with domain", "(uid=alice@example.com)", true},
		{"and filter", "(&(uid=alice)(ou=users))", true},
		{"or filter", "(|(uid=alice)(uid=bob))", true},
		{"not filter", "(!(uid=alice))", true},
		{"wildcard", "(uid=*)", true},
		{"substring", "(uid=ali*)", true},
		{"objectClass filter", "(objectClass=person)", true},
		{"complex nested", "(&(uid=alice)(|(ou=users)(ou=admins)))", true},
		{"empty parentheses", "()", true}, // Syntactically valid
		{"exactly max length", string(make([]byte, 512)), true},

		// Invalid filters - injection/dangerous characters
		{"null byte injection", "(uid=test\x00evil)", false},
		{"cr injection", "(uid=test\revil)", false},
		{"lf injection", "(uid=test\nevil)", false},
		{"crlf injection", "(uid=test\r\nevil)", false},
		{"semicolon", "(uid=test;DROP)", false},

		// Invalid filters - length
		{"exceeds max length", string(make([]byte, 513)), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidateLDAPFilter(tt.filter)
			if got != tt.valid {
				t.Errorf("ValidateLDAPFilter(%q) = %v, want %v", tt.filter, got, tt.valid)
			}
		})
	}
}

func TestParseUserEmail(t *testing.T) {
	tests := []struct {
		name    string
		dn      string
		baseDN  string
		email   string
		success bool
	}{
		// Valid cases
		{"standard user dn", "uid=alice@example.com,ou=users,dc=test,dc=app", "dc=test,dc=app", "alice@example.com", true},
		{"user with dots in local", "uid=alice.smith@example.com,ou=users,dc=test,dc=app", "dc=test,dc=app", "alice.smith@example.com", true},
		{"user with numbers", "uid=user123@example.com,ou=users,dc=test,dc=app", "dc=test,dc=app", "user123@example.com", true},
		{"user with dashes", "uid=user-name@example.org,ou=users,dc=test,dc=app", "dc=test,dc=app", "user-name@example.org", true},
		{"complex domain", "uid=test@sub.example.co.uk,ou=users,dc=test,dc=app", "dc=test,dc=app", "test@sub.example.co.uk", true},

		// Invalid cases - no @ sign
		{"no @ sign", "uid=alice,ou=users,dc=test,dc=app", "dc=test,dc=app", "", false},
		{"non-email in uid", "uid=localonly,ou=users,dc=test,dc=app", "dc=test,dc=app", "", false},

		// Invalid cases - wrong DN format
		{"wrong DN format", "cn=alice@example.com,ou=users,dc=test,dc=app", "dc=test,dc=app", "", false},
		{"no ou component", "uid=alice@example.com,dc=test,dc=app", "dc=test,dc=app", "", false},
		{"empty dn", "", "dc=test,dc=app", "", false},
		{"malformed uid", "uid=alice@example.com", "dc=test,dc=app", "", false}, // No comma after UID

		// Edge cases
		{"baseDN ignored in parse", "uid=alice@example.com,ou=users,dc=other,dc=org", "dc=test,dc=app", "alice@example.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotEmail, gotSuccess := ParseUserEmail(tt.dn, tt.baseDN)
			if gotSuccess != tt.success {
				t.Errorf("ParseUserEmail(%q, %q) success = %v, want %v", tt.dn, tt.baseDN, gotSuccess, tt.success)
			}
			if gotSuccess && gotEmail != tt.email {
				t.Errorf("ParseUserEmail(%q, %q) email = %q, want %q", tt.dn, tt.baseDN, gotEmail, tt.email)
			}
		})
	}
}

func TestMapUserEmailToDN(t *testing.T) {
	tests := []struct {
		name    string
		email   string
		baseDN  string
		expected string
	}{
		{"standard email and base", "alice@example.com", "dc=test,dc=app", "uid=alice@example.com,ou=users,dc=test,dc=app"},
		{"email with dots", "alice.smith@example.com", "dc=test,dc=app", "uid=alice.smith@example.com,ou=users,dc=test,dc=app"},
		{"nested base", "user@example.com", "dc=sub,dc=test,dc=app", "uid=user@example.com,ou=users,dc=sub,dc=test,dc=app"},
		{"empty email", "", "dc=test,dc=app", "uid=,ou=users,dc=test,dc=app"},
		{"empty baseDN", "alice@example.com", "", "uid=alice@example.com,ou=users,"},
		{"both empty", "", "", "uid=,ou=users,"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MapUserEmailToDN(tt.email, tt.baseDN)
			if got != tt.expected {
				t.Errorf("MapUserEmailToDN(%q, %q) = %q, want %q", tt.email, tt.baseDN, got, tt.expected)
			}
		})
	}
}

func TestMapGroupNameToDN(t *testing.T) {
	tests := []struct {
		name    string
		groupName string
		baseDN  string
		expected string
	}{
		{"standard group", "admins", "dc=test,dc=app", "cn=admins,ou=groups,dc=test,dc=app"},
		{"group with spaces", "Test Group", "dc=test,dc=app", "cn=Test Group,ou=groups,dc=test,dc=app"},
		{"group with hyphens", "test-group", "dc=test,dc=app", "cn=test-group,ou=groups,dc=test,dc=app"},
		{"nested base", "users", "dc=sub,dc=test,dc=app", "cn=users,ou=groups,dc=sub,dc=test,dc=app"},
		{"empty group name", "", "dc=test,dc=app", "cn=,ou=groups,dc=test,dc=app"},
		{"empty baseDN", "admins", "", "cn=admins,ou=groups,"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MapGroupNameToDN(tt.groupName, tt.baseDN)
			if got != tt.expected {
				t.Errorf("MapGroupNameToDN(%q, %q) = %q, want %q", tt.groupName, tt.baseDN, got, tt.expected)
			}
		})
	}
}

func TestNormalizeDN(t *testing.T) {
	tests := []struct {
		name    string
		dn      string
		expected string
	}{
		{"uppercase", "UID=ALICE@EXAMPLE.COM,OU=USERS,DC=TEST,DC=APP", "uid=alice@example.com,ou=users,dc=test,dc=app"},
		{"mixed case", "Uid=Alice@Example.Com,Ou=Users,Dc=Test,Dc=App", "uid=alice@example.com,ou=users,dc=test,dc=app"},
		{"leading spaces", "  uid=alice@example.com,ou=users,dc=test,dc=app", "uid=alice@example.com,ou=users,dc=test,dc=app"},
		{"trailing spaces", "uid=alice@example.com,ou=users,dc=test,dc=app  ", "uid=alice@example.com,ou=users,dc=test,dc=app"},
		{"both spaces and case", "  UID=ALICE@EXAMPLE.COM,OU=USERS,DC=TEST,DC=APP  ", "uid=alice@example.com,ou=users,dc=test,dc=app"},
		{"already normalized", "uid=alice@example.com,ou=users,dc=test,dc=app", "uid=alice@example.com,ou=users,dc=test,dc=app"},
		{"empty string", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizeDN(tt.dn)
			if got != tt.expected {
				t.Errorf("NormalizeDN(%q) = %q, want %q", tt.dn, got, tt.expected)
			}
		})
	}
}

func TestIsSuffixOf(t *testing.T) {
	tests := []struct {
		name     string
		dn       string
		base     string
		expected bool
	}{
		// True cases - DN is within the subtree of base
		{"exact match", "dc=test,dc=app", "dc=test,dc=app", true},
		{"user under base", "uid=alice,ou=users,dc=test,dc=app", "dc=test,dc=app", true},
		{"nested ou under base", "uid=alice,ou=admins,ou=users,dc=test,dc=app", "dc=test,dc=app", true},
		{"ou is base", "ou=users,dc=test,dc=app", "dc=test,dc=app", true},

		// True cases - case insensitivity
		{"uppercase dn", "UID=ALICE,OU=USERS,DC=TEST,DC=APP", "dc=test,dc=app", true},
		{"uppercase base", "uid=alice,ou=users,dc=test,dc=app", "DC=TEST,DC=APP", true},
		{"both uppercase", "UID=ALICE,OU=USERS,DC=TEST,DC=APP", "DC=TEST,DC=APP", true},

		// True cases - whitespace handling
		{"dn with spaces", "  uid=alice,ou=users,dc=test,dc=app  ", "  dc=test,dc=app  ", true},

		// False cases - DN is not under base
		{"different base", "uid=alice,ou=users,dc=other,dc=org", "dc=test,dc=app", false},
		{"different dc level", "uid=alice,ou=users,dc=test,dc=com", "dc=test,dc=app", false},
		{"base longer than dn", "dc=test", "dc=test,dc=app", false},
		{"partial dc match only", "uid=alice,dc=test", "dc=test,dc=app", false},

		// Edge cases
		{"empty dn", "", "dc=test,dc=app", false},
		{"empty base", "dc=test,dc=app", "", false},
		{"both empty", "", "", true}, // Empty suffix of empty is true
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsSuffixOf(tt.dn, tt.base)
			if got != tt.expected {
				t.Errorf("IsSuffixOf(%q, %q) = %v, want %v", tt.dn, tt.base, got, tt.expected)
			}
		})
	}
}
