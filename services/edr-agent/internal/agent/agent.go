// Package agent implements the core EDR agent functionality
package agent

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/elastic/go-sysinfo"
	"github.com/penguintech/skauswatch/edr-agent/internal/collectors"
	"github.com/penguintech/skauswatch/edr-agent/internal/reporters"
	"go.uber.org/zap"
)

// Config holds the agent configuration
type Config struct {
	ManagerURL      string
	APIKey          string
	AgentID         string
	HeartbeatSecs   int
	EventBufferSize int
	Collectors      CollectorConfig
}

// CollectorConfig holds collector settings
type CollectorConfig struct {
	ProcessEnabled  bool
	FileEnabled     bool
	NetworkEnabled  bool
	RegistryEnabled bool
}

// Agent is the main EDR agent struct
type Agent struct {
	config     Config
	logger     *zap.Logger
	reporter   *reporters.RESTReporter
	collectors []collectors.Collector
	events     chan Event
	wg         sync.WaitGroup
	hostname   string
	osInfo     string
}

// Event represents a security event
type Event struct {
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	AgentID   string                 `json:"agent_id"`
	Hostname  string                 `json:"hostname"`
	Severity  string                 `json:"severity"`
	Data      map[string]interface{} `json:"data"`
}

// New creates a new EDR agent
func New(config Config, logger *zap.Logger) (*Agent, error) {
	// Get host information
	host, err := sysinfo.Host()
	if err != nil {
		return nil, fmt.Errorf("failed to get host info: %w", err)
	}

	info := host.Info()
	hostname := info.Hostname
	osInfo := fmt.Sprintf("%s %s", info.OS.Name, info.OS.Version)

	// Generate agent ID if not provided
	if config.AgentID == "" {
		config.AgentID = generateAgentID(hostname)
	}

	// Create reporter
	reporter := reporters.NewRESTReporter(
		config.ManagerURL,
		config.APIKey,
		config.AgentID,
		logger,
	)

	agent := &Agent{
		config:   config,
		logger:   logger,
		reporter: reporter,
		events:   make(chan Event, config.EventBufferSize),
		hostname: hostname,
		osInfo:   osInfo,
	}

	// Initialize collectors
	if err := agent.initCollectors(); err != nil {
		return nil, fmt.Errorf("failed to initialize collectors: %w", err)
	}

	return agent, nil
}

// initCollectors initializes enabled collectors
func (a *Agent) initCollectors() error {
	if a.config.Collectors.ProcessEnabled {
		pc, err := collectors.NewProcessCollector(a.logger)
		if err != nil {
			a.logger.Warn("Failed to initialize process collector", zap.Error(err))
		} else {
			a.collectors = append(a.collectors, pc)
		}
	}

	if a.config.Collectors.FileEnabled {
		fc, err := collectors.NewFileCollector(a.logger)
		if err != nil {
			a.logger.Warn("Failed to initialize file collector", zap.Error(err))
		} else {
			a.collectors = append(a.collectors, fc)
		}
	}

	if a.config.Collectors.NetworkEnabled {
		nc, err := collectors.NewNetworkCollector(a.logger)
		if err != nil {
			a.logger.Warn("Failed to initialize network collector", zap.Error(err))
		} else {
			a.collectors = append(a.collectors, nc)
		}
	}

	a.logger.Info("Collectors initialized",
		zap.Int("count", len(a.collectors)),
	)

	return nil
}

// Run starts the agent
func (a *Agent) Run(ctx context.Context) error {
	a.logger.Info("Starting EDR agent",
		zap.String("agent_id", a.config.AgentID),
		zap.String("hostname", a.hostname),
		zap.String("manager_url", a.config.ManagerURL),
	)

	// Register with manager
	if err := a.register(ctx); err != nil {
		return fmt.Errorf("failed to register: %w", err)
	}

	// Start heartbeat
	a.wg.Add(1)
	go a.heartbeatLoop(ctx)

	// Start event reporter
	a.wg.Add(1)
	go a.eventReporterLoop(ctx)

	// Start collectors
	for _, collector := range a.collectors {
		a.wg.Add(1)
		go a.runCollector(ctx, collector)
	}

	// Wait for shutdown
	<-ctx.Done()
	a.logger.Info("Shutting down agent")

	// Wait for all goroutines to finish
	a.wg.Wait()

	return nil
}

// register registers the agent with the manager
func (a *Agent) register(ctx context.Context) error {
	registration := reporters.AgentRegistration{
		AgentID:      a.config.AgentID,
		Hostname:     a.hostname,
		OS:           a.osInfo,
		AgentVersion: "1.0.0",
		Collectors:   a.getCollectorNames(),
	}

	return a.reporter.Register(ctx, registration)
}

// heartbeatLoop sends periodic heartbeats
func (a *Agent) heartbeatLoop(ctx context.Context) {
	defer a.wg.Done()

	ticker := time.NewTicker(time.Duration(a.config.HeartbeatSecs) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := a.reporter.Heartbeat(ctx); err != nil {
				a.logger.Warn("Heartbeat failed", zap.Error(err))
			}
		}
	}
}

// eventReporterLoop batches and sends events
func (a *Agent) eventReporterLoop(ctx context.Context) {
	defer a.wg.Done()

	batch := make([]reporters.EDREvent, 0, 100)
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// Send remaining events
			if len(batch) > 0 {
				a.sendEventBatch(context.Background(), batch)
			}
			return

		case event := <-a.events:
			edrEvent := reporters.EDREvent{
				Type:      event.Type,
				Timestamp: event.Timestamp,
				Severity:  event.Severity,
				Data:      event.Data,
			}
			batch = append(batch, edrEvent)

			// Send if batch is full
			if len(batch) >= 100 {
				a.sendEventBatch(ctx, batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			// Send batch periodically
			if len(batch) > 0 {
				a.sendEventBatch(ctx, batch)
				batch = batch[:0]
			}
		}
	}
}

// sendEventBatch sends a batch of events to the manager
func (a *Agent) sendEventBatch(ctx context.Context, events []reporters.EDREvent) {
	if err := a.reporter.ReportEvents(ctx, events); err != nil {
		a.logger.Warn("Failed to send events",
			zap.Error(err),
			zap.Int("event_count", len(events)),
		)
	} else {
		a.logger.Debug("Events sent",
			zap.Int("count", len(events)),
		)
	}
}

// runCollector runs a collector and forwards events
func (a *Agent) runCollector(ctx context.Context, collector collectors.Collector) {
	defer a.wg.Done()

	eventChan := collector.Events()

	for {
		select {
		case <-ctx.Done():
			collector.Stop()
			return
		case rawEvent, ok := <-eventChan:
			if !ok {
				return
			}

			event := Event{
				Type:      rawEvent.Type,
				Timestamp: rawEvent.Timestamp,
				AgentID:   a.config.AgentID,
				Hostname:  a.hostname,
				Severity:  rawEvent.Severity,
				Data:      rawEvent.Data,
			}

			select {
			case a.events <- event:
			default:
				a.logger.Warn("Event buffer full, dropping event")
			}
		}
	}
}

// getCollectorNames returns the names of active collectors
func (a *Agent) getCollectorNames() []string {
	names := make([]string, len(a.collectors))
	for i, c := range a.collectors {
		names[i] = c.Name()
	}
	return names
}

// generateAgentID generates a unique agent ID
func generateAgentID(hostname string) string {
	timestamp := time.Now().Unix()
	pid := os.Getpid()
	return fmt.Sprintf("%s-%d-%d", hostname, pid, timestamp)
}
