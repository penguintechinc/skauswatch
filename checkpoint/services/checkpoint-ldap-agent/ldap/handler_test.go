package ldapagent

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/nmcclain/ldap"
	"go.uber.org/zap"

	"github.com/penguintechinc/skauswatch/checkpoint/ldap-agent/metrics"
)

// mockGRPCClient implements GRPCClient interface
type mockGRPCClient struct {
	bindResult   bool
	bindError    error
	bindUserUUID string
	searchResult []LDAPEntry
	searchError  error
	compareResult bool
	compareError  error
}

func (m *mockGRPCClient) Bind(dn, password, agentID, clientIP string) (bool, string, error) {
	return m.bindResult, m.bindUserUUID, m.bindError
}

func (m *mockGRPCClient) Search(baseDN, filter string, attributes []string, scope, sizeLimit int32, agentID string) ([]LDAPEntry, error) {
	return m.searchResult, m.searchError
}

func (m *mockGRPCClient) Compare(dn, attribute, value, agentID string) (bool, error) {
	return m.compareResult, m.compareError
}

func (m *mockGRPCClient) Close() error {
	return nil
}

// mockRESTClient implements RESTClient interface
type mockRESTClient struct {
	bindResult   bool
	bindError    error
	bindUserUUID string
	searchResult []LDAPEntry
	searchError  error
}

func (m *mockRESTClient) Bind(dn, password, agentID string) (bool, string, error) {
	return m.bindResult, m.bindUserUUID, m.bindError
}

func (m *mockRESTClient) Search(baseDN, filter string, attributes []string, scope int32, agentID string) ([]LDAPEntry, error) {
	return m.searchResult, m.searchError
}

// fakeConn implements net.Conn interface for testing
type fakeConn struct {
	remoteAddr string
}

func (f *fakeConn) Read(b []byte) (n int, err error) {
	return 0, errors.New("not implemented")
}

func (f *fakeConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (f *fakeConn) Close() error {
	return nil
}

func (f *fakeConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
}

func (f *fakeConn) RemoteAddr() net.Addr {
	addr, _ := net.ResolveTCPAddr("tcp", f.remoteAddr)
	return addr
}

func (f *fakeConn) SetDeadline(t time.Time) error {
	return nil
}

func (f *fakeConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (f *fakeConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func newFakeConn(remoteAddr string) net.Conn {
	return &fakeConn{remoteAddr: remoteAddr}
}

func TestBind_ValidCredentials_gRPCSuccess(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := metrics.NewMetrics()
	grpc := &mockGRPCClient{bindResult: true, bindUserUUID: "user-123"}
	rest := &mockRESTClient{}
	s := NewServer(grpc, rest, "dc=test,dc=app", "agent-1", logger, m)

	conn := newFakeConn("192.168.1.1:5389")
	result, err := s.Bind("uid=alice@test.com,ou=users,dc=test,dc=app", "correctpassword", conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != ldap.LDAPResultSuccess {
		t.Errorf("expected LDAPResultSuccess, got %v", result)
	}
}

func TestBind_InvalidCredentials(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := metrics.NewMetrics()
	grpc := &mockGRPCClient{bindResult: false}
	rest := &mockRESTClient{}
	s := NewServer(grpc, rest, "dc=test,dc=app", "agent-1", logger, m)

	conn := newFakeConn("192.168.1.1:5389")
	result, err := s.Bind("uid=alice@test.com,ou=users,dc=test,dc=app", "wrongpassword", conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != ldap.LDAPResultInvalidCredentials {
		t.Errorf("expected LDAPResultInvalidCredentials, got %v", result)
	}
}

func TestBind_InvalidDN_NullByte(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := metrics.NewMetrics()
	grpc := &mockGRPCClient{}
	rest := &mockRESTClient{}
	s := NewServer(grpc, rest, "dc=test,dc=app", "agent-1", logger, m)

	conn := newFakeConn("192.168.1.1:5389")
	result, err := s.Bind("uid=alice\x00evil,ou=users,dc=test,dc=app", "password", conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != ldap.LDAPResultInvalidDNSyntax {
		t.Errorf("expected LDAPResultInvalidDNSyntax, got %v", result)
	}
}

func TestBind_InvalidDN_CRLFInjection(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := metrics.NewMetrics()
	grpc := &mockGRPCClient{}
	rest := &mockRESTClient{}
	s := NewServer(grpc, rest, "dc=test,dc=app", "agent-1", logger, m)

	conn := newFakeConn("192.168.1.1:5389")
	result, err := s.Bind("uid=alice\r\nevil,ou=users,dc=test,dc=app", "password", conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != ldap.LDAPResultInvalidDNSyntax {
		t.Errorf("expected LDAPResultInvalidDNSyntax, got %v", result)
	}
}

func TestBind_gRPCError_FallbackToREST_Success(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := metrics.NewMetrics()
	grpc := &mockGRPCClient{bindError: errors.New("connection refused")}
	rest := &mockRESTClient{bindResult: true, bindUserUUID: "user-456"}
	s := NewServer(grpc, rest, "dc=test,dc=app", "agent-1", logger, m)

	conn := newFakeConn("192.168.1.1:5389")
	result, err := s.Bind("uid=bob@test.com,ou=users,dc=test,dc=app", "password", conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != ldap.LDAPResultSuccess {
		t.Errorf("expected LDAPResultSuccess after REST fallback, got %v", result)
	}
}

func TestBind_gRPCError_RESTError_OperationsError(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := metrics.NewMetrics()
	grpc := &mockGRPCClient{bindError: errors.New("grpc failed")}
	rest := &mockRESTClient{bindError: errors.New("rest failed")}
	s := NewServer(grpc, rest, "dc=test,dc=app", "agent-1", logger, m)

	conn := newFakeConn("192.168.1.1:5389")
	result, err := s.Bind("uid=carol@test.com,ou=users,dc=test,dc=app", "password", conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != ldap.LDAPResultOperationsError {
		t.Errorf("expected LDAPResultOperationsError, got %v", result)
	}
}

func TestSearch_ValidRequest(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := metrics.NewMetrics()
	entries := []LDAPEntry{
		{
			DN: "uid=alice@test.com,ou=users,dc=test,dc=app",
			Attributes: map[string][]string{
				"uid": {"alice@test.com"},
				"mail": {"alice@example.com"},
			},
		},
	}
	grpc := &mockGRPCClient{searchResult: entries}
	rest := &mockRESTClient{}
	s := NewServer(grpc, rest, "dc=test,dc=app", "agent-1", logger, m)

	conn := newFakeConn("192.168.1.1:5389")
	req := ldap.SearchRequest{
		BaseDN:   "ou=users,dc=test,dc=app",
		Filter:   "(uid=alice*)",
		Scope:    2, // LDAP_SCOPE_SUBTREE
		SizeLimit: 100,
	}

	result, err := s.Search("uid=alice,ou=users,dc=test,dc=app", req.BaseDN, req, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ResultCode != ldap.LDAPResultSuccess {
		t.Errorf("expected LDAPResultSuccess, got %v", result.ResultCode)
	}
	if len(result.Entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(result.Entries))
	}
	if result.Entries[0].DN != "uid=alice@test.com,ou=users,dc=test,dc=app" {
		t.Errorf("unexpected DN: %s", result.Entries[0].DN)
	}
}

func TestSearch_InvalidFilter(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := metrics.NewMetrics()
	grpc := &mockGRPCClient{}
	rest := &mockRESTClient{}
	s := NewServer(grpc, rest, "dc=test,dc=app", "agent-1", logger, m)

	conn := newFakeConn("192.168.1.1:5389")
	req := ldap.SearchRequest{
		BaseDN:    "ou=users,dc=test,dc=app",
		Filter:    "(uid=test\x00evil)", // Null byte injection
		Scope:     2,
		SizeLimit: 100,
	}

	result, err := s.Search("uid=alice,ou=users,dc=test,dc=app", req.BaseDN, req, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ResultCode != ldap.LDAPResultUnwillingToPerform {
		t.Errorf("expected LDAPResultUnwillingToPerform, got %v", result.ResultCode)
	}
}

func TestSearch_InvalidBaseDN(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := metrics.NewMetrics()
	grpc := &mockGRPCClient{}
	rest := &mockRESTClient{}
	s := NewServer(grpc, rest, "dc=test,dc=app", "agent-1", logger, m)

	conn := newFakeConn("192.168.1.1:5389")
	req := ldap.SearchRequest{
		BaseDN:    "ou=users\x00evil,dc=test,dc=app", // Null byte in DN
		Filter:    "(uid=alice*)",
		Scope:     2,
		SizeLimit: 100,
	}

	result, err := s.Search("uid=alice,ou=users,dc=test,dc=app", req.BaseDN, req, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ResultCode != ldap.LDAPResultInvalidDNSyntax {
		t.Errorf("expected LDAPResultInvalidDNSyntax, got %v", result.ResultCode)
	}
}

func TestSearch_SizeLimit_Capped(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := metrics.NewMetrics()

	// Create mock to track what sizeLimit was passed
	capturedSizeLimit := int32(0)
	grpc := &mockGRPCClient{
		searchResult: []LDAPEntry{},
	}
	// Wrap to capture the actual call
	originalSearch := grpc.Search
	grpc.Search = func(baseDN, filter string, attributes []string, scope, sizeLimit int32, agentID string) ([]LDAPEntry, error) {
		capturedSizeLimit = sizeLimit
		return originalSearch(baseDN, filter, attributes, scope, sizeLimit, agentID)
	}

	rest := &mockRESTClient{}
	s := NewServer(grpc, rest, "dc=test,dc=app", "agent-1", logger, m)

	conn := newFakeConn("192.168.1.1:5389")
	req := ldap.SearchRequest{
		BaseDN:    "ou=users,dc=test,dc=app",
		Filter:    "(uid=*)",
		Scope:     2,
		SizeLimit: 5000, // Larger than maxSizeLimit (1000)
	}

	_, err := s.Search("uid=alice,ou=users,dc=test,dc=app", req.BaseDN, req, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedSizeLimit != 1000 {
		t.Errorf("expected sizeLimit to be capped to 1000, got %d", capturedSizeLimit)
	}
}

func TestSearch_SizeLimit_ZeroDefaulted(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := metrics.NewMetrics()

	capturedSizeLimit := int32(0)
	grpc := &mockGRPCClient{
		searchResult: []LDAPEntry{},
	}
	grpc.Search = func(baseDN, filter string, attributes []string, scope, sizeLimit int32, agentID string) ([]LDAPEntry, error) {
		capturedSizeLimit = sizeLimit
		return []LDAPEntry{}, nil
	}

	rest := &mockRESTClient{}
	s := NewServer(grpc, rest, "dc=test,dc=app", "agent-1", logger, m)

	conn := newFakeConn("192.168.1.1:5389")
	req := ldap.SearchRequest{
		BaseDN:    "ou=users,dc=test,dc=app",
		Filter:    "(uid=*)",
		Scope:     2,
		SizeLimit: 0, // Zero should be defaulted
	}

	_, err := s.Search("uid=alice,ou=users,dc=test,dc=app", req.BaseDN, req, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if capturedSizeLimit != 1000 {
		t.Errorf("expected sizeLimit to default to 1000, got %d", capturedSizeLimit)
	}
}

func TestSearch_gRPCError_FallbackToREST(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := metrics.NewMetrics()
	entries := []LDAPEntry{
		{
			DN:         "uid=bob@test.com,ou=users,dc=test,dc=app",
			Attributes: map[string][]string{"uid": {"bob@test.com"}},
		},
	}
	grpc := &mockGRPCClient{searchError: errors.New("grpc unavailable")}
	rest := &mockRESTClient{searchResult: entries}
	s := NewServer(grpc, rest, "dc=test,dc=app", "agent-1", logger, m)

	conn := newFakeConn("192.168.1.1:5389")
	req := ldap.SearchRequest{
		BaseDN:    "ou=users,dc=test,dc=app",
		Filter:    "(uid=bob*)",
		Scope:     2,
		SizeLimit: 100,
	}

	result, err := s.Search("uid=admin,ou=users,dc=test,dc=app", req.BaseDN, req, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ResultCode != ldap.LDAPResultSuccess {
		t.Errorf("expected LDAPResultSuccess after REST fallback, got %v", result.ResultCode)
	}
	if len(result.Entries) != 1 {
		t.Errorf("expected 1 entry, got %d", len(result.Entries))
	}
}

func TestSearch_BothFailures_OperationsError(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := metrics.NewMetrics()
	grpc := &mockGRPCClient{searchError: errors.New("grpc failed")}
	rest := &mockRESTClient{searchError: errors.New("rest failed")}
	s := NewServer(grpc, rest, "dc=test,dc=app", "agent-1", logger, m)

	conn := newFakeConn("192.168.1.1:5389")
	req := ldap.SearchRequest{
		BaseDN:    "ou=users,dc=test,dc=app",
		Filter:    "(uid=*)",
		Scope:     2,
		SizeLimit: 100,
	}

	result, err := s.Search("uid=admin,ou=users,dc=test,dc=app", req.BaseDN, req, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ResultCode != ldap.LDAPResultOperationsError {
		t.Errorf("expected LDAPResultOperationsError, got %v", result.ResultCode)
	}
}

func TestSearch_EmptyResult(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := metrics.NewMetrics()
	grpc := &mockGRPCClient{searchResult: []LDAPEntry{}}
	rest := &mockRESTClient{}
	s := NewServer(grpc, rest, "dc=test,dc=app", "agent-1", logger, m)

	conn := newFakeConn("192.168.1.1:5389")
	req := ldap.SearchRequest{
		BaseDN:    "ou=users,dc=test,dc=app",
		Filter:    "(uid=nonexistent*)",
		Scope:     2,
		SizeLimit: 100,
	}

	result, err := s.Search("uid=admin,ou=users,dc=test,dc=app", req.BaseDN, req, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ResultCode != ldap.LDAPResultSuccess {
		t.Errorf("expected LDAPResultSuccess, got %v", result.ResultCode)
	}
	if len(result.Entries) != 0 {
		t.Errorf("expected 0 entries, got %d", len(result.Entries))
	}
}

func TestSearch_MultipleEntries(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	m := metrics.NewMetrics()
	entries := []LDAPEntry{
		{
			DN: "uid=user1@test.com,ou=users,dc=test,dc=app",
			Attributes: map[string][]string{
				"uid": {"user1@test.com"},
				"cn": {"User One"},
			},
		},
		{
			DN: "uid=user2@test.com,ou=users,dc=test,dc=app",
			Attributes: map[string][]string{
				"uid": {"user2@test.com"},
				"cn": {"User Two"},
			},
		},
		{
			DN: "uid=user3@test.com,ou=users,dc=test,dc=app",
			Attributes: map[string][]string{
				"uid": {"user3@test.com"},
				"cn": {"User Three"},
			},
		},
	}
	grpc := &mockGRPCClient{searchResult: entries}
	rest := &mockRESTClient{}
	s := NewServer(grpc, rest, "dc=test,dc=app", "agent-1", logger, m)

	conn := newFakeConn("192.168.1.1:5389")
	req := ldap.SearchRequest{
		BaseDN:    "ou=users,dc=test,dc=app",
		Filter:    "(uid=user*)",
		Scope:     2,
		SizeLimit: 100,
	}

	result, err := s.Search("uid=admin,ou=users,dc=test,dc=app", req.BaseDN, req, conn)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Entries) != 3 {
		t.Errorf("expected 3 entries, got %d", len(result.Entries))
	}
	for i, entry := range result.Entries {
		if entry.DN != entries[i].DN {
			t.Errorf("entry %d DN mismatch: %s vs %s", i, entry.DN, entries[i].DN)
		}
	}
}
