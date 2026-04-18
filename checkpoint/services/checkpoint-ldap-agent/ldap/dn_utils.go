package ldapagent

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	// validDNPattern allows standard DN characters
	validDNPattern = regexp.MustCompile(`^[a-zA-Z0-9=,@._\- ]+$`)
	// injectionChars catches dangerous characters
	injectionChars = regexp.MustCompile(`[;\x00\r\n<>]`)
	// emailInDNPattern extracts email from uid= component
	emailInDNPattern = regexp.MustCompile(`uid=([^,]+),`)
	// filterInjection catches null bytes and CRLF in filters
	filterInjection = regexp.MustCompile(`[\x00\r\n;]`)
)

const (
	maxDNLength     = 512
	maxFilterLength = 512
)

// ParseUserEmail extracts email from a DN of the form "uid=user@example.com,ou=users,dc=...".
// Returns ("", false) if the DN doesn't match the expected format.
func ParseUserEmail(dn, baseDN string) (string, bool) {
	matches := emailInDNPattern.FindStringSubmatch(dn)
	if len(matches) < 2 {
		return "", false
	}
	email := matches[1]
	if !strings.Contains(email, "@") {
		return "", false
	}
	return email, true
}

// ValidateDN checks a DN for injection characters and reasonable length.
// Returns false if the DN contains injection characters or exceeds maxDNLength.
func ValidateDN(dn string) bool {
	if len(dn) > maxDNLength {
		return false
	}
	if injectionChars.MatchString(dn) {
		return false
	}
	return true
}

// ValidateLDAPFilter validates a filter string for injection and reasonable length.
// Returns false if:
//   - length > maxFilterLength
//   - contains null bytes (\x00)
//   - contains CRLF (\r\n)
//   - contains semicolons (not valid in LDAP filter syntax)
func ValidateLDAPFilter(filter string) bool {
	if len(filter) > maxFilterLength {
		return false
	}
	if filterInjection.MatchString(filter) {
		return false
	}
	return true
}

// MapUserEmailToDN builds a user DN from an email address.
// Returns "uid=email,ou=users,baseDN".
func MapUserEmailToDN(email, baseDN string) string {
	return fmt.Sprintf("uid=%s,ou=users,%s", email, baseDN)
}

// MapGroupNameToDN builds a group DN from a group name.
// Returns "cn=name,ou=groups,baseDN".
func MapGroupNameToDN(name, baseDN string) string {
	return fmt.Sprintf("cn=%s,ou=groups,%s", name, baseDN)
}

// NormalizeDN lowercases and trims whitespace from a DN for consistent comparison.
func NormalizeDN(dn string) string {
	return strings.ToLower(strings.TrimSpace(dn))
}

// IsSuffixOf reports whether dn is within the subtree of base.
func IsSuffixOf(dn, base string) bool {
	dn = NormalizeDN(dn)
	base = NormalizeDN(base)
	return strings.HasSuffix(dn, ","+base) || dn == base
}
