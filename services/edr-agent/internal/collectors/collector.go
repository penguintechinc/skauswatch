// Package collectors implements system event collectors
package collectors

import (
	"time"
)

// Event represents a collected system event
type Event struct {
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Severity  string                 `json:"severity"`
	Data      map[string]interface{} `json:"data"`
}

// Collector interface for all event collectors
type Collector interface {
	// Name returns the collector name
	Name() string

	// Start begins collecting events
	Start() error

	// Stop stops the collector
	Stop() error

	// Events returns the event channel
	Events() <-chan Event
}

// Severity levels
const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Event types
const (
	EventTypeProcess  = "process"
	EventTypeFile     = "file"
	EventTypeNetwork  = "network"
	EventTypeRegistry = "registry"
)
