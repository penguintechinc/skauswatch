// Package grpc provides the gRPC client for checkpoint-core communication.
package grpc

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	ldapagent "github.com/penguintechinc/skauswatch/checkpoint/ldap-agent/ldap"
	checkpointpb "github.com/penguintechinc/skauswatch/checkpoint/ldap-agent/proto"
)

const (
	bindTimeout   = 5 * time.Second
	searchTimeout = 10 * time.Second
	dialTimeout   = 10 * time.Second
)

// Client wraps the gRPC connection to checkpoint-core.
type Client struct {
	conn    *grpc.ClientConn
	svc     checkpointpb.CheckpointServiceClient
	logger  *zap.Logger
	agentID string
}

// NewClient creates a new gRPC client connected to host:port.
// Uses insecure credentials — mTLS is handled at the service mesh / SPIFFE layer.
func NewClient(host, port, agentID string, logger *zap.Logger) (*Client, error) {
	target := fmt.Sprintf("%s:%s", host, port)
	dialCtx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()

	conn, err := grpc.DialContext( //nolint:staticcheck
		dialCtx,
		target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to dial checkpoint-core at %s: %w", target, err)
	}

	logger.Info("gRPC connection established", zap.String("target", target))

	return &Client{
		conn:    conn,
		svc:     checkpointpb.NewCheckpointServiceClient(conn),
		logger:  logger,
		agentID: agentID,
	}, nil
}

// Bind performs an LDAP bind via gRPC.
func (c *Client) Bind(dn, password, agentID, clientIP string) (bool, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), bindTimeout)
	defer cancel()

	resp, err := c.svc.LdapBind(ctx, &checkpointpb.LdapBindRequest{
		Dn:       dn,
		Password: password,
		AgentId:  agentID,
		ClientIp: clientIP,
	})
	if err != nil {
		return false, "", fmt.Errorf("grpc LdapBind: %w", err)
	}
	return resp.Success, resp.UserUuid, nil
}

// Search performs an LDAP search via gRPC.
func (c *Client) Search(baseDN, filter string, attributes []string, scope, sizeLimit int32, agentID string) ([]ldapagent.LDAPEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), searchTimeout)
	defer cancel()

	resp, err := c.svc.LdapSearch(ctx, &checkpointpb.LdapSearchRequest{
		BaseDn:     baseDN,
		Filter:     filter,
		Attributes: attributes,
		Scope:      scope,
		SizeLimit:  sizeLimit,
		AgentId:    agentID,
	})
	if err != nil {
		return nil, fmt.Errorf("grpc LdapSearch: %w", err)
	}

	entries := make([]ldapagent.LDAPEntry, 0, len(resp.Entries))
	for _, e := range resp.Entries {
		entry := ldapagent.LDAPEntry{
			DN:         e.Dn,
			Attributes: make(map[string][]string, len(e.Attributes)),
		}
		for _, attr := range e.Attributes {
			entry.Attributes[attr.Name] = attr.Values
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// Compare performs an LDAP compare via gRPC.
func (c *Client) Compare(dn, attribute, value, agentID string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), bindTimeout)
	defer cancel()

	resp, err := c.svc.LdapCompare(ctx, &checkpointpb.LdapCompareRequest{
		Dn:        dn,
		Attribute: attribute,
		Value:     value,
		AgentId:   agentID,
	})
	if err != nil {
		return false, fmt.Errorf("grpc LdapCompare: %w", err)
	}
	return resp.Matched, nil
}

// Register registers this agent instance with checkpoint-core.
func (c *Client) Register(agentID, hostname, version, siteName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), bindTimeout)
	defer cancel()

	resp, err := c.svc.RegisterAgent(ctx, &checkpointpb.RegisterAgentRequest{
		AgentId:  agentID,
		Hostname: hostname,
		Version:  version,
		SiteName: siteName,
	})
	if err != nil {
		return fmt.Errorf("grpc RegisterAgent: %w", err)
	}
	if !resp.Success {
		return fmt.Errorf("agent registration rejected: %s", resp.Error)
	}
	return nil
}

// Heartbeat sends a keepalive heartbeat to checkpoint-core.
func (c *Client) Heartbeat(agentID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), bindTimeout)
	defer cancel()

	_, err := c.svc.AgentHeartbeat(ctx, &checkpointpb.HeartbeatRequest{
		AgentId:   agentID,
		Timestamp: time.Now().Unix(),
	})
	if err != nil {
		return fmt.Errorf("grpc AgentHeartbeat: %w", err)
	}
	return nil
}

// Close closes the gRPC connection.
func (c *Client) Close() error {
	return c.conn.Close()
}
