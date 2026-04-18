// Package reporters tests
package reporters

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.uber.org/zap"
)

func newTestLogger() *zap.Logger {
	logger, _ := zap.NewDevelopment()
	return logger
}

func TestNewRESTReporter(t *testing.T) {
	logger := newTestLogger()
	reporter := NewRESTReporter("http://localhost:5000", "test-key", "agent-001", logger)

	if reporter.managerURL != "http://localhost:5000" {
		t.Errorf("Expected managerURL http://localhost:5000, got %s", reporter.managerURL)
	}
	if reporter.apiKey != "test-key" {
		t.Errorf("Expected apiKey test-key, got %s", reporter.apiKey)
	}
	if reporter.agentID != "agent-001" {
		t.Errorf("Expected agentID agent-001, got %s", reporter.agentID)
	}
}

func TestRegister(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.URL.Path != "/api/v1/edr/register" {
			t.Errorf("Expected path /api/v1/edr/register, got %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		if r.Header.Get("X-API-Key") != "test-key" {
			t.Errorf("Expected API key test-key, got %s", r.Header.Get("X-API-Key"))
		}
		if r.Header.Get("X-Agent-ID") != "agent-001" {
			t.Errorf("Expected agent ID agent-001, got %s", r.Header.Get("X-Agent-ID"))
		}

		// Decode body
		var reg AgentRegistration
		if err := json.NewDecoder(r.Body).Decode(&reg); err != nil {
			t.Errorf("Failed to decode registration body: %v", err)
		}
		if reg.AgentID != "agent-001" {
			t.Errorf("Expected agent_id agent-001, got %s", reg.AgentID)
		}

		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	logger := newTestLogger()
	reporter := NewRESTReporter(server.URL, "test-key", "agent-001", logger)

	reg := AgentRegistration{
		AgentID:      "agent-001",
		Hostname:     "test-host",
		OS:           "Linux 6.1",
		AgentVersion: "1.0.0",
		Collectors:   []string{"process", "network"},
	}

	err := reporter.Register(context.Background(), reg)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
}

func TestRegisterAcceptsOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger := newTestLogger()
	reporter := NewRESTReporter(server.URL, "test-key", "agent-001", logger)

	reg := AgentRegistration{AgentID: "agent-001"}
	err := reporter.Register(context.Background(), reg)
	if err != nil {
		t.Fatalf("Register should succeed on 200 OK, got: %v", err)
	}
}

func TestRegisterFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	logger := newTestLogger()
	reporter := NewRESTReporter(server.URL, "test-key", "agent-001", logger)

	reg := AgentRegistration{AgentID: "agent-001"}
	err := reporter.Register(context.Background(), reg)
	if err == nil {
		t.Error("Expected error for 500 response")
	}
}

func TestRegisterUnauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	logger := newTestLogger()
	reporter := NewRESTReporter(server.URL, "bad-key", "agent-001", logger)

	reg := AgentRegistration{AgentID: "agent-001"}
	err := reporter.Register(context.Background(), reg)
	if err == nil {
		t.Error("Expected error for 401 response")
	}
}

func TestHeartbeat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/edr/heartbeat" {
			t.Errorf("Expected path /api/v1/edr/heartbeat, got %s", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger := newTestLogger()
	reporter := NewRESTReporter(server.URL, "test-key", "agent-001", logger)

	err := reporter.Heartbeat(context.Background())
	if err != nil {
		t.Fatalf("Heartbeat failed: %v", err)
	}
}

func TestHeartbeatFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	logger := newTestLogger()
	reporter := NewRESTReporter(server.URL, "test-key", "agent-001", logger)

	err := reporter.Heartbeat(context.Background())
	if err == nil {
		t.Error("Expected error for 503 response")
	}
}

func TestReportEvents(t *testing.T) {
	var receivedBatch EventBatch
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/edr/events" {
			t.Errorf("Expected path /api/v1/edr/events, got %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&receivedBatch); err != nil {
			t.Errorf("Failed to decode event batch: %v", err)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	logger := newTestLogger()
	reporter := NewRESTReporter(server.URL, "test-key", "agent-001", logger)

	events := []EDREvent{
		{Type: "process", Timestamp: time.Now(), Severity: "high", Data: map[string]interface{}{"pid": 1234}},
		{Type: "network", Timestamp: time.Now(), Severity: "medium", Data: map[string]interface{}{"port": 443}},
	}

	err := reporter.ReportEvents(context.Background(), events)
	if err != nil {
		t.Fatalf("ReportEvents failed: %v", err)
	}

	if len(receivedBatch.Events) != 2 {
		t.Errorf("Expected 2 events, got %d", len(receivedBatch.Events))
	}
}

func TestReportEventsAcceptsOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger := newTestLogger()
	reporter := NewRESTReporter(server.URL, "test-key", "agent-001", logger)

	events := []EDREvent{
		{Type: "process", Timestamp: time.Now(), Severity: "low", Data: map[string]interface{}{}},
	}

	err := reporter.ReportEvents(context.Background(), events)
	if err != nil {
		t.Fatalf("ReportEvents should succeed on 200 OK, got: %v", err)
	}
}

func TestReportEventsFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer server.Close()

	logger := newTestLogger()
	reporter := NewRESTReporter(server.URL, "test-key", "agent-001", logger)

	events := []EDREvent{
		{Type: "process", Timestamp: time.Now(), Severity: "high", Data: map[string]interface{}{}},
	}

	err := reporter.ReportEvents(context.Background(), events)
	if err == nil {
		t.Error("Expected error for 400 response")
	}
}

func TestReportEvent(t *testing.T) {
	var receivedBatch EventBatch
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedBatch) //nolint:errcheck
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	logger := newTestLogger()
	reporter := NewRESTReporter(server.URL, "test-key", "agent-001", logger)

	event := EDREvent{
		Type:      "file",
		Timestamp: time.Now(),
		Severity:  "critical",
		Data:      map[string]interface{}{"path": "/etc/passwd"},
	}

	err := reporter.ReportEvent(context.Background(), event)
	if err != nil {
		t.Fatalf("ReportEvent failed: %v", err)
	}

	if len(receivedBatch.Events) != 1 {
		t.Errorf("Expected 1 event in batch, got %d", len(receivedBatch.Events))
	}
}

func TestGetConfig(t *testing.T) {
	expectedConfig := map[string]interface{}{
		"heartbeat_interval": float64(30),
		"collectors": map[string]interface{}{
			"process": true,
			"network": true,
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/edr/config" {
			t.Errorf("Expected path /api/v1/edr/config, got %s", r.URL.Path)
		}
		if r.Method != "GET" {
			t.Errorf("Expected GET, got %s", r.Method)
		}
		json.NewEncoder(w).Encode(expectedConfig) //nolint:errcheck
	}))
	defer server.Close()

	logger := newTestLogger()
	reporter := NewRESTReporter(server.URL, "test-key", "agent-001", logger)

	config, err := reporter.GetConfig(context.Background())
	if err != nil {
		t.Fatalf("GetConfig failed: %v", err)
	}

	if config["heartbeat_interval"] != float64(30) {
		t.Errorf("Expected heartbeat_interval 30, got %v", config["heartbeat_interval"])
	}
}

func TestGetConfigFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	logger := newTestLogger()
	reporter := NewRESTReporter(server.URL, "test-key", "agent-001", logger)

	_, err := reporter.GetConfig(context.Background())
	if err == nil {
		t.Error("Expected error for 404 response")
	}
}

func TestSetHeaders(t *testing.T) {
	logger := newTestLogger()
	reporter := NewRESTReporter("http://localhost", "my-key", "my-agent", logger)

	req, err := http.NewRequest("GET", "http://localhost", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	reporter.setHeaders(req)

	if req.Header.Get("Content-Type") != "application/json" {
		t.Errorf("Missing or wrong Content-Type header, got: %s", req.Header.Get("Content-Type"))
	}
	if req.Header.Get("X-API-Key") != "my-key" {
		t.Errorf("Wrong X-API-Key header, got: %s", req.Header.Get("X-API-Key"))
	}
	if req.Header.Get("X-Agent-ID") != "my-agent" {
		t.Errorf("Wrong X-Agent-ID header, got: %s", req.Header.Get("X-Agent-ID"))
	}
	if req.Header.Get("User-Agent") != "SkausWatch-EDR-Agent/1.0" {
		t.Errorf("Wrong User-Agent header, got: %s", req.Header.Get("User-Agent"))
	}
}

func TestAgentRegistrationJSONFields(t *testing.T) {
	reg := AgentRegistration{
		AgentID:      "agent-123",
		Hostname:     "my-host",
		OS:           "Linux 6.1",
		AgentVersion: "2.0.0",
		Collectors:   []string{"process", "file", "network"},
	}

	data, err := json.Marshal(reg)
	if err != nil {
		t.Fatalf("Failed to marshal AgentRegistration: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Failed to unmarshal to map: %v", err)
	}

	expectedKeys := []string{"agent_id", "hostname", "os", "agent_version", "collectors"}
	for _, key := range expectedKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("Expected JSON key '%s' not found", key)
		}
	}
}

func TestEventBatchJSONFields(t *testing.T) {
	batch := EventBatch{
		Events: []EDREvent{
			{Type: "process", Timestamp: time.Now(), Severity: "high", Data: map[string]interface{}{}},
		},
	}

	data, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("Failed to marshal EventBatch: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Failed to unmarshal to map: %v", err)
	}

	if _, ok := raw["events"]; !ok {
		t.Error("Expected JSON key 'events' not found in EventBatch")
	}
}
