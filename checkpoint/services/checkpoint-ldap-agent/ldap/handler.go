package ldapagent

import (
	"net"
	"time"

	"github.com/nmcclain/ldap"
	"go.uber.org/zap"
)

const (
	maxSizeLimit  = 1000
	bindTimeout   = 5 * time.Second
	searchTimeout = 10 * time.Second
)

// Bind handles LDAP simple bind requests.
// Implements ldap.BindHandler.
func (s *Server) Bind(bindDN, bindSimplePW string, conn net.Conn) (ldap.LDAPResultCode, error) {
	start := time.Now()
	clientIP := conn.RemoteAddr().String()

	// Validate DN — never log password
	if !ValidateDN(bindDN) {
		s.logger.Warn("bind rejected: invalid DN", zap.String("dn", sanitizeDN(bindDN)))
		s.metrics.BindRequests.WithLabelValues("error").Inc()
		return ldap.LDAPResultInvalidDNSyntax, nil
	}

	s.logger.Info("ldap bind attempt", zap.String("dn", bindDN), zap.String("client_ip", clientIP))

	// Primary: gRPC to checkpoint-core
	success, _, err := s.grpcClient.Bind(bindDN, bindSimplePW, s.agentID, clientIP)
	if err != nil {
		s.logger.Warn("grpc bind failed, trying REST fallback",
			zap.String("dn", bindDN),
			zap.Error(err),
		)
		// Fallback: REST to skauswatch-core
		success, _, err = s.restClient.Bind(bindDN, bindSimplePW, s.agentID)
		if err != nil {
			s.logger.Error("rest fallback bind failed", zap.String("dn", bindDN), zap.Error(err))
			s.metrics.BindRequests.WithLabelValues("error").Inc()
			s.metrics.BindLatency.Observe(time.Since(start).Seconds())
			return ldap.LDAPResultOperationsError, nil
		}
	}

	s.metrics.BindLatency.Observe(time.Since(start).Seconds())

	if success {
		s.logger.Info("ldap bind success", zap.String("dn", bindDN))
		s.metrics.BindRequests.WithLabelValues("success").Inc()
		return ldap.LDAPResultSuccess, nil
	}

	s.logger.Info("ldap bind failed: invalid credentials", zap.String("dn", bindDN))
	s.metrics.BindRequests.WithLabelValues("invalid_credentials").Inc()
	return ldap.LDAPResultInvalidCredentials, nil
}

// Search handles LDAP search requests.
// Implements ldap.SearchHandler.
func (s *Server) Search(boundDN, searchBaseDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	start := time.Now()

	filter := searchReq.Filter
	attributes := searchReq.Attributes
	scope := searchReq.Scope
	sizeLimit := searchReq.SizeLimit

	// Validate inputs
	if !ValidateDN(searchBaseDN) {
		s.logger.Warn("search rejected: invalid baseDN", zap.String("base_dn", sanitizeDN(searchBaseDN)))
		s.metrics.SearchRequests.WithLabelValues("error").Inc()
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultInvalidDNSyntax}, nil
	}
	if !ValidateLDAPFilter(filter) {
		s.logger.Warn("search rejected: invalid filter")
		s.metrics.SearchRequests.WithLabelValues("error").Inc()
		return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultUnwillingToPerform}, nil
	}

	// Enforce size limit
	if sizeLimit <= 0 || sizeLimit > maxSizeLimit {
		sizeLimit = maxSizeLimit
	}

	s.logger.Info("ldap search",
		zap.String("bound_dn", boundDN),
		zap.String("base_dn", searchBaseDN),
		zap.String("filter", filter),
		zap.Int("scope", scope),
	)

	// Primary: gRPC
	entries, err := s.grpcClient.Search(searchBaseDN, filter, attributes, int32(scope), int32(sizeLimit), s.agentID)
	if err != nil {
		s.logger.Warn("grpc search failed, trying REST fallback",
			zap.String("base_dn", searchBaseDN),
			zap.Error(err),
		)
		// Fallback: REST
		entries, err = s.restClient.Search(searchBaseDN, filter, attributes, int32(scope), s.agentID)
		if err != nil {
			s.logger.Error("rest fallback search failed", zap.String("base_dn", searchBaseDN), zap.Error(err))
			s.metrics.SearchRequests.WithLabelValues("error").Inc()
			s.metrics.SearchLatency.Observe(time.Since(start).Seconds())
			return ldap.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, nil
		}
	}

	// Map LDAPEntry → ldap.Entry
	ldapEntries := make([]*ldap.Entry, 0, len(entries))
	for _, e := range entries {
		ldapEntry := &ldap.Entry{DN: e.DN}
		for attrName, attrVals := range e.Attributes {
			ldapEntry.Attributes = append(ldapEntry.Attributes, &ldap.EntryAttribute{
				Name:   attrName,
				Values: attrVals,
			})
		}
		ldapEntries = append(ldapEntries, ldapEntry)
	}

	s.metrics.SearchRequests.WithLabelValues("success").Inc()
	s.metrics.SearchLatency.Observe(time.Since(start).Seconds())

	s.logger.Info("ldap search complete",
		zap.String("base_dn", searchBaseDN),
		zap.Int("result_count", len(ldapEntries)),
	)

	return ldap.ServerSearchResult{
		Entries:    ldapEntries,
		Referrals:  []string{},
		Controls:   []ldap.Control{},
		ResultCode: ldap.LDAPResultSuccess,
	}, nil
}

// sanitizeDN returns a safe representation of a DN for logging (truncated).
func sanitizeDN(dn string) string {
	if len(dn) > 64 {
		return dn[:64] + "...[truncated]"
	}
	return dn
}
