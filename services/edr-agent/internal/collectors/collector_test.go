// Package collectors tests
package collectors

import (
	"testing"
	"time"
)

func TestEventCreation(t *testing.T) {
	event := Event{
		Type:      EventTypeProcess,
		Timestamp: time.Now(),
		Severity:  SeverityHigh,
		Data: map[string]interface{}{
			"pid": 1234,
		},
	}

	if event.Type != "process" {
		t.Errorf("Expected type 'process', got '%s'", event.Type)
	}
	if event.Severity != "high" {
		t.Errorf("Expected severity 'high', got '%s'", event.Severity)
	}
}

func TestSeverityConstants(t *testing.T) {
	tests := []struct {
		name     string
		severity string
		expected string
	}{
		{"Info", SeverityInfo, "info"},
		{"Low", SeverityLow, "low"},
		{"Medium", SeverityMedium, "medium"},
		{"High", SeverityHigh, "high"},
		{"Critical", SeverityCritical, "critical"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.severity != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, tt.severity)
			}
		})
	}
}

func TestEventTypeConstants(t *testing.T) {
	tests := []struct {
		name      string
		eventType string
		expected  string
	}{
		{"Process", EventTypeProcess, "process"},
		{"File", EventTypeFile, "file"},
		{"Network", EventTypeNetwork, "network"},
		{"Registry", EventTypeRegistry, "registry"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.eventType != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, tt.eventType)
			}
		})
	}
}

func TestEventTimestamp(t *testing.T) {
	before := time.Now()
	event := Event{
		Type:      EventTypeFile,
		Timestamp: time.Now(),
		Severity:  SeverityLow,
	}
	after := time.Now()

	if event.Timestamp.Before(before) || event.Timestamp.After(after) {
		t.Error("Event timestamp should be between before and after")
	}
}

func TestEventDataMap(t *testing.T) {
	event := Event{
		Type:      EventTypeNetwork,
		Timestamp: time.Now(),
		Severity:  SeverityMedium,
		Data: map[string]interface{}{
			"src_ip":   "192.168.1.1",
			"dst_port": 443,
			"protocol": "tcp",
		},
	}

	if event.Data["src_ip"] != "192.168.1.1" {
		t.Errorf("Expected src_ip '192.168.1.1', got '%v'", event.Data["src_ip"])
	}
	if event.Data["dst_port"] != 443 {
		t.Errorf("Expected dst_port 443, got '%v'", event.Data["dst_port"])
	}
}

func TestAllSeverityLevelsDistinct(t *testing.T) {
	levels := []string{SeverityInfo, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	seen := make(map[string]bool)
	for _, level := range levels {
		if seen[level] {
			t.Errorf("Duplicate severity level: %s", level)
		}
		seen[level] = true
	}
}

func TestAllEventTypesDistinct(t *testing.T) {
	types := []string{EventTypeProcess, EventTypeFile, EventTypeNetwork, EventTypeRegistry}
	seen := make(map[string]bool)
	for _, et := range types {
		if seen[et] {
			t.Errorf("Duplicate event type: %s", et)
		}
		seen[et] = true
	}
}
