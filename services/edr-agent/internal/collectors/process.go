package collectors

import (
	"sync"
	"time"

	"github.com/penguintech/skauswatch/edr-agent/internal/logging"
	"github.com/shirou/gopsutil/v4/process"
	"go.uber.org/zap"
)

// ProcessCollector monitors process creation and termination
type ProcessCollector struct {
	logger       *logging.SanitizedLogger
	events       chan Event
	stopChan     chan struct{}
	running      bool
	mu           sync.Mutex
	knownPids    map[int32]processInfo
	pollInterval time.Duration
}

type processInfo struct {
	Name       string
	Cmdline    string
	Username   string
	CreateTime int64
}

// NewProcessCollector creates a new process collector
func NewProcessCollector(logger *logging.SanitizedLogger) (*ProcessCollector, error) {
	return &ProcessCollector{
		logger:       logger,
		events:       make(chan Event, 1000),
		stopChan:     make(chan struct{}),
		knownPids:    make(map[int32]processInfo),
		pollInterval: 1 * time.Second,
	}, nil
}

// Name returns the collector name
func (c *ProcessCollector) Name() string {
	return "process"
}

// Start begins collecting process events
func (c *ProcessCollector) Start() error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return nil
	}
	c.running = true
	c.mu.Unlock()

	// Initialize known processes
	c.initKnownProcesses()

	go c.collectLoop()
	c.logger.Info("Process collector started")
	return nil
}

// Stop stops the collector
func (c *ProcessCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	close(c.stopChan)
	c.running = false
	c.logger.Info("Process collector stopped")
	return nil
}

// Events returns the event channel
func (c *ProcessCollector) Events() <-chan Event {
	return c.events
}

func (c *ProcessCollector) initKnownProcesses() {
	procs, err := process.Processes()
	if err != nil {
		c.logger.Warn("Failed to list processes", zap.Error(err))
		return
	}

	for _, p := range procs {
		info := c.getProcessInfo(p)
		c.knownPids[p.Pid] = info
	}
}

func (c *ProcessCollector) collectLoop() {
	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			c.checkProcesses()
		}
	}
}

func (c *ProcessCollector) checkProcesses() {
	procs, err := process.Processes()
	if err != nil {
		c.logger.Warn("Failed to list processes", zap.Error(err))
		return
	}

	currentPids := make(map[int32]bool)

	for _, p := range procs {
		currentPids[p.Pid] = true

		if _, known := c.knownPids[p.Pid]; !known {
			// New process
			info := c.getProcessInfo(p)
			c.knownPids[p.Pid] = info

			event := Event{
				Type:      EventTypeProcess,
				Timestamp: time.Now(),
				Severity:  c.determineProcessSeverity(info),
				Data: map[string]interface{}{
					"action":      "created",
					"pid":         p.Pid,
					"name":        info.Name,
					"cmdline":     info.Cmdline,
					"username":    info.Username,
					"create_time": info.CreateTime,
				},
			}

			c.emitEvent(event)
		}
	}

	// Check for terminated processes
	for pid, info := range c.knownPids {
		if !currentPids[pid] {
			delete(c.knownPids, pid)

			event := Event{
				Type:      EventTypeProcess,
				Timestamp: time.Now(),
				Severity:  SeverityInfo,
				Data: map[string]interface{}{
					"action":   "terminated",
					"pid":      pid,
					"name":     info.Name,
					"username": info.Username,
				},
			}

			c.emitEvent(event)
		}
	}
}

func (c *ProcessCollector) getProcessInfo(p *process.Process) processInfo {
	info := processInfo{}

	name, err := p.Name()
	if err == nil {
		info.Name = name
	}

	cmdline, err := p.Cmdline()
	if err == nil {
		info.Cmdline = cmdline
	}

	username, err := p.Username()
	if err == nil {
		info.Username = username
	}

	createTime, err := p.CreateTime()
	if err == nil {
		info.CreateTime = createTime
	}

	return info
}

func (c *ProcessCollector) determineProcessSeverity(info processInfo) string {
	// Check for suspicious process names or patterns
	suspiciousNames := []string{
		"mimikatz", "psexec", "powershell", "cmd",
		"nc", "netcat", "nmap", "whoami",
	}

	for _, name := range suspiciousNames {
		if info.Name == name {
			return SeverityHigh
		}
	}

	// Check for processes running as root/SYSTEM
	if info.Username == "root" || info.Username == "SYSTEM" {
		return SeverityMedium
	}

	return SeverityLow
}

func (c *ProcessCollector) emitEvent(event Event) {
	select {
	case c.events <- event:
	default:
		c.logger.Warn("Event channel full, dropping event")
	}
}
