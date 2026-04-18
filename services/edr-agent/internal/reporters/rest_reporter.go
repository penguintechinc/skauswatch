// Package reporters implements event reporting to the manager
package reporters

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/penguintech/skauswatch/edr-agent/internal/logging"
	"go.uber.org/zap"
)

// RESTReporter reports events to the manager via REST API
type RESTReporter struct {
	client     *http.Client
	managerURL string
	apiKey     string
	agentID    string
	logger     *logging.SanitizedLogger
}

// AgentRegistration contains agent registration data
type AgentRegistration struct {
	AgentID      string   `json:"agent_id"`
	Hostname     string   `json:"hostname"`
	OS           string   `json:"os"`
	AgentVersion string   `json:"agent_version"`
	Collectors   []string `json:"collectors"`
}

// EDREvent represents a security event
type EDREvent struct {
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Severity  string                 `json:"severity"`
	Data      map[string]interface{} `json:"data"`
}

// EventBatch contains multiple events
type EventBatch struct {
	Events []EDREvent `json:"events"`
}

// NewRESTReporter creates a new REST reporter
func NewRESTReporter(managerURL, apiKey, agentID string, logger *logging.SanitizedLogger) *RESTReporter {
	return &RESTReporter{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		managerURL: managerURL,
		apiKey:     apiKey,
		agentID:    agentID,
		logger:     logger,
	}
}

// Register registers the agent with the manager
func (r *RESTReporter) Register(ctx context.Context, reg AgentRegistration) error {
	endpoint := fmt.Sprintf("%s/api/v1/edr/register", r.managerURL)

	payload, err := json.Marshal(reg)
	if err != nil {
		return fmt.Errorf("failed to marshal registration: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	r.setHeaders(req)

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("registration request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("registration failed with status: %d", resp.StatusCode)
	}

	r.logger.Info("Agent registered successfully",
		zap.String("agent_id", reg.AgentID),
	)

	return nil
}

// Heartbeat sends a heartbeat to the manager
func (r *RESTReporter) Heartbeat(ctx context.Context) error {
	endpoint := fmt.Sprintf("%s/api/v1/edr/heartbeat", r.managerURL)

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	r.setHeaders(req)

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("heartbeat request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("heartbeat failed with status: %d", resp.StatusCode)
	}

	return nil
}

// ReportEvent reports a single event
func (r *RESTReporter) ReportEvent(ctx context.Context, event EDREvent) error {
	return r.ReportEvents(ctx, []EDREvent{event})
}

// ReportEvents reports multiple events
func (r *RESTReporter) ReportEvents(ctx context.Context, events []EDREvent) error {
	endpoint := fmt.Sprintf("%s/api/v1/edr/events", r.managerURL)

	batch := EventBatch{Events: events}
	payload, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("failed to marshal events: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	r.setHeaders(req)

	resp, err := r.client.Do(req)
	if err != nil {
		return fmt.Errorf("event report request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("event report failed with status: %d", resp.StatusCode)
	}

	return nil
}

// GetConfig retrieves configuration from the manager
func (r *RESTReporter) GetConfig(ctx context.Context) (map[string]interface{}, error) {
	endpoint := fmt.Sprintf("%s/api/v1/edr/config", r.managerURL)

	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	r.setHeaders(req)

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("config request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("config request failed with status: %d", resp.StatusCode)
	}

	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode config: %w", err)
	}

	return config, nil
}

// setHeaders sets common headers for requests
func (r *RESTReporter) setHeaders(req *http.Request) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", r.apiKey)
	req.Header.Set("X-Agent-ID", r.agentID)
	req.Header.Set("User-Agent", "SkausWatch-EDR-Agent/1.0")
}
