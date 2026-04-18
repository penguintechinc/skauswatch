// Package rest provides the REST fallback client for skauswatch-core.
package rest

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-resty/resty/v2"
	"go.uber.org/zap"

	ldapagent "github.com/penguintechinc/skauswatch/checkpoint/ldap-agent/ldap"
)

const (
	bindEndpoint   = "/api/v1/ldap/bind"
	searchEndpoint = "/api/v1/ldap/search"
	requestTimeout = 8 * time.Second
)

// bindRequest is the JSON body sent to the bind endpoint.
type bindRequest struct {
	DN      string `json:"dn"`
	Password string `json:"password"`
	AgentID string `json:"agent_id"`
}

// bindResponse is the JSON response from the bind endpoint.
type bindResponse struct {
	Success  bool   `json:"success"`
	UserUUID string `json:"user_uuid"`
	Error    string `json:"error,omitempty"`
}

// searchRequest is the JSON body sent to the search endpoint.
type searchRequest struct {
	BaseDN     string   `json:"base_dn"`
	Filter     string   `json:"filter"`
	Attributes []string `json:"attributes"`
	Scope      int32    `json:"scope"`
	AgentID    string   `json:"agent_id"`
}

// searchResponse is the JSON response from the search endpoint.
type searchResponse struct {
	Entries []searchEntry `json:"entries"`
	Error   string        `json:"error,omitempty"`
}

type searchEntry struct {
	DN         string              `json:"dn"`
	Attributes map[string][]string `json:"attributes"`
}

// FallbackClient makes REST calls to skauswatch-core when gRPC is unavailable.
type FallbackClient struct {
	client  *resty.Client
	baseURL string
	logger  *zap.Logger
}

// NewFallbackClient constructs a FallbackClient pointing at baseURL.
func NewFallbackClient(baseURL string, logger *zap.Logger) *FallbackClient {
	r := resty.New().
		SetBaseURL(baseURL).
		SetTimeout(requestTimeout).
		SetHeader("Content-Type", "application/json").
		SetHeader("Accept", "application/json")

	return &FallbackClient{
		client:  r,
		baseURL: baseURL,
		logger:  logger,
	}
}

// Bind sends a bind request to POST {baseURL}/api/v1/ldap/bind.
func (c *FallbackClient) Bind(dn, password, agentID string) (bool, string, error) {
	var result bindResponse

	resp, err := c.client.R().
		SetBody(bindRequest{DN: dn, Password: password, AgentID: agentID}).
		SetResult(&result).
		Post(bindEndpoint)
	if err != nil {
		return false, "", fmt.Errorf("rest bind request failed: %w", err)
	}
	if resp.StatusCode() == http.StatusUnauthorized {
		return false, "", nil
	}
	if resp.IsError() {
		return false, "", fmt.Errorf("rest bind returned HTTP %d: %s", resp.StatusCode(), result.Error)
	}

	c.logger.Debug("rest fallback bind",
		zap.String("dn", dn),
		zap.Bool("success", result.Success),
	)
	return result.Success, result.UserUUID, nil
}

// Search sends a search request to POST {baseURL}/api/v1/ldap/search.
func (c *FallbackClient) Search(baseDN, filter string, attributes []string, scope int32, agentID string) ([]ldapagent.LDAPEntry, error) {
	var result searchResponse

	resp, err := c.client.R().
		SetBody(searchRequest{
			BaseDN:     baseDN,
			Filter:     filter,
			Attributes: attributes,
			Scope:      scope,
			AgentID:    agentID,
		}).
		SetResult(&result).
		Post(searchEndpoint)
	if err != nil {
		return nil, fmt.Errorf("rest search request failed: %w", err)
	}
	if resp.IsError() {
		return nil, fmt.Errorf("rest search returned HTTP %d: %s", resp.StatusCode(), result.Error)
	}

	entries := make([]ldapagent.LDAPEntry, 0, len(result.Entries))
	for _, e := range result.Entries {
		entries = append(entries, ldapagent.LDAPEntry{
			DN:         e.DN,
			Attributes: e.Attributes,
		})
	}

	c.logger.Debug("rest fallback search",
		zap.String("base_dn", baseDN),
		zap.Int("result_count", len(entries)),
	)
	return entries, nil
}
