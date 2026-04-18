// Package ldapagent implements the LDAP server for checkpoint-ldap-agent.
package ldapagent

import (
	"fmt"
	"net"

	"github.com/nmcclain/ldap"
	"go.uber.org/zap"

	"github.com/penguintechinc/skauswatch/checkpoint/ldap-agent/metrics"
)

// GRPCClient is the interface for checkpoint-core gRPC operations.
type GRPCClient interface {
	Bind(dn, password, agentID, clientIP string) (bool, string, error)
	Search(baseDN, filter string, attributes []string, scope int32, sizeLimit int32, agentID string) ([]LDAPEntry, error)
	Compare(dn, attribute, value, agentID string) (bool, error)
	Close() error
}

// RESTClient is the interface for skauswatch-core REST fallback operations.
type RESTClient interface {
	Bind(dn, password, agentID string) (bool, string, error)
	Search(baseDN, filter string, attributes []string, scope int32, agentID string) ([]LDAPEntry, error)
}

// LDAPEntry represents a single LDAP directory entry.
type LDAPEntry struct {
	DN         string
	Attributes map[string][]string
}

// Server is the LDAP server for the checkpoint agent.
type Server struct {
	grpcClient GRPCClient
	restClient RESTClient
	baseDN     string
	agentID    string
	logger     *zap.Logger
	metrics    *metrics.Metrics
	server     *ldap.Server
	listener   net.Listener
}

// NewServer constructs a new LDAP Server.
func NewServer(grpcClient GRPCClient, restClient RESTClient, baseDN, agentID string, logger *zap.Logger, m *metrics.Metrics) *Server {
	s := &Server{
		grpcClient: grpcClient,
		restClient: restClient,
		baseDN:     baseDN,
		agentID:    agentID,
		logger:     logger,
		metrics:    m,
	}
	s.server = ldap.NewServer()
	// Register handlers
	s.server.BindFunc("", s)
	s.server.SearchFunc("", s)
	s.server.CloseFunc("", s)
	return s
}

// Start begins listening on the given port (non-blocking).
func (s *Server) Start(port int) error {
	addr := fmt.Sprintf(":%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = ln
	go func() {
		if err := s.server.Serve(ln); err != nil {
			// Serve returns when listener is closed — only log if unexpected
			s.logger.Debug("LDAP server stopped", zap.Error(err))
		}
	}()
	return nil
}

// Stop performs a graceful shutdown of the LDAP server.
func (s *Server) Stop() {
	s.server.Stop()
	if s.listener != nil {
		s.listener.Close() //nolint:errcheck
	}
}

// Close satisfies the nmcclain/ldap CloseHandler interface.
func (s *Server) Close(boundDN string, conn net.Conn) error {
	s.logger.Debug("LDAP connection closed", zap.String("remote", conn.RemoteAddr().String()))
	return nil
}
