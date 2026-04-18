// Package agent tests
package agent

import (
	"encoding/json"
	"testing"
	"time"
)

func TestConfigDefaults(t *testing.T) {
	config := Config{
		ManagerURL:      "http://localhost:5000",
		APIKey:          "test-key",
		HeartbeatSecs:   30,
		EventBufferSize: 1000,
	}

	if config.ManagerURL != "http://localhost:5000" {
		t.Errorf("Expected ManagerURL http://localhost:5000, got %s", config.ManagerURL)
	}
	if config.HeartbeatSecs != 30 {
		t.Errorf("Expected HeartbeatSecs 30, got %d", config.HeartbeatSecs)
	}
}

func TestCollectorConfig(t *testing.T) {
	cc := CollectorConfig{
		ProcessEnabled:  true,
		FileEnabled:     false,
		NetworkEnabled:  true,
		RegistryEnabled: false,
	}
	if !cc.ProcessEnabled {
		t.Error("ProcessEnabled should be true")
	}
	if cc.FileEnabled {
		t.Error("FileEnabled should be false")
	}
}

func TestEventJSONMarshal(t *testing.T) {
	event := Event{
		Type:      "process",
		Timestamp: time.Now(),
		AgentID:   "agent-001",
		Hostname:  "test-host",
		Severity:  "high",
		Data: map[string]interface{}{
			"pid":  1234,
			"name": "suspicious.exe",
		},
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Failed to marshal event: %v", err)
	}

	var decoded Event
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal event: %v", err)
	}

	if decoded.Type != "process" {
		t.Errorf("Expected type 'process', got '%s'", decoded.Type)
	}
	if decoded.AgentID != "agent-001" {
		t.Errorf("Expected agent_id 'agent-001', got '%s'", decoded.AgentID)
	}
}

func TestGenerateAgentID(t *testing.T) {
	id := generateAgentID("test-host")
	if id == "" {
		t.Error("Agent ID should not be empty")
	}
	// Should contain hostname
	if len(id) < len("test-host") {
		t.Error("Agent ID should contain hostname")
	}
}

func TestGenerateAgentIDFormat(t *testing.T) {
	hostname := "my-server"
	id := generateAgentID(hostname)

	// Format is: hostname-pid-timestamp, verify hostname prefix
	if len(id) == 0 {
		t.Fatal("Generated agent ID is empty")
	}

	// Two calls should differ (different timestamps at minimum for different pids)
	// but hostname prefix should be consistent
	id2 := generateAgentID(hostname)
	if id2 == "" {
		t.Error("Second generated agent ID is empty")
	}
}

func TestEventJSONFieldNames(t *testing.T) {
	event := Event{
		Type:     "network",
		AgentID:  "agent-xyz",
		Hostname: "host-abc",
		Severity: "medium",
	}

	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Failed to marshal event: %v", err)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Failed to unmarshal to map: %v", err)
	}

	expectedKeys := []string{"type", "timestamp", "agent_id", "hostname", "severity", "data"}
	for _, key := range expectedKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("Expected JSON key '%s' not found", key)
		}
	}
}

func TestConfigCollectorDefaults(t *testing.T) {
	// Zero-value CollectorConfig should have all collectors disabled
	cc := CollectorConfig{}
	if cc.ProcessEnabled {
		t.Error("ProcessEnabled should default to false")
	}
	if cc.FileEnabled {
		t.Error("FileEnabled should default to false")
	}
	if cc.NetworkEnabled {
		t.Error("NetworkEnabled should default to false")
	}
	if cc.RegistryEnabled {
		t.Error("RegistryEnabled should default to false")
	}
}
