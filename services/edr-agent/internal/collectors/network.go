package collectors

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/penguintech/skauswatch/edr-agent/internal/logging"
	psutilnet "github.com/shirou/gopsutil/v4/net"
	"go.uber.org/zap"
)

// NetworkCollector monitors network connections
type NetworkCollector struct {
	logger          *logging.SanitizedLogger
	events          chan Event
	stopChan        chan struct{}
	running         bool
	mu              sync.Mutex
	knownConns      map[string]connInfo
	pollInterval    time.Duration
	suspiciousPorts map[uint32]string
}

type connInfo struct {
	LocalAddr  string
	LocalPort  uint32
	RemoteAddr string
	RemotePort uint32
	Status     string
	PID        int32
}

// NewNetworkCollector creates a new network collector
func NewNetworkCollector(logger *logging.SanitizedLogger) (*NetworkCollector, error) {
	// Suspicious ports commonly used by malware/attackers
	suspiciousPorts := map[uint32]string{
		4444:  "Metasploit default",
		5555:  "Android ADB",
		6666:  "IRC backdoor",
		6667:  "IRC",
		31337: "Back Orifice",
		12345: "NetBus",
		1234:  "Common RAT",
		8080:  "HTTP proxy",
		3389:  "RDP",
		5900:  "VNC",
		22:    "SSH",
		23:    "Telnet",
	}

	return &NetworkCollector{
		logger:         logger,
		events:         make(chan Event, 1000),
		stopChan:       make(chan struct{}),
		knownConns:     make(map[string]connInfo),
		pollInterval:   5 * time.Second,
		suspiciousPorts: suspiciousPorts,
	}, nil
}

// Name returns the collector name
func (c *NetworkCollector) Name() string {
	return "network"
}

// Start begins collecting network events
func (c *NetworkCollector) Start() error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return nil
	}
	c.running = true
	c.mu.Unlock()

	// Initialize known connections
	c.initKnownConnections()

	go c.collectLoop()
	c.logger.Info("Network collector started")
	return nil
}

// Stop stops the collector
func (c *NetworkCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	close(c.stopChan)
	c.running = false
	c.logger.Info("Network collector stopped")
	return nil
}

// Events returns the event channel
func (c *NetworkCollector) Events() <-chan Event {
	return c.events
}

func (c *NetworkCollector) initKnownConnections() {
	conns, err := psutilnet.Connections("all")
	if err != nil {
		c.logger.Warn("Failed to list connections", zap.Error(err))
		return
	}

	for _, conn := range conns {
		key := c.connKey(conn)
		c.knownConns[key] = c.toConnInfo(conn)
	}
}

func (c *NetworkCollector) collectLoop() {
	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			c.checkConnections()
		}
	}
}

func (c *NetworkCollector) checkConnections() {
	conns, err := psutilnet.Connections("all")
	if err != nil {
		c.logger.Warn("Failed to list connections", zap.Error(err))
		return
	}

	currentConns := make(map[string]bool)

	for _, conn := range conns {
		key := c.connKey(conn)
		currentConns[key] = true

		if _, known := c.knownConns[key]; !known {
			// New connection
			info := c.toConnInfo(conn)
			c.knownConns[key] = info

			// Only emit events for established connections
			if conn.Status == "ESTABLISHED" || conn.Status == "LISTEN" {
				event := Event{
					Type:      EventTypeNetwork,
					Timestamp: time.Now(),
					Severity:  c.determineSeverity(info),
					Data: map[string]interface{}{
						"action":      "connected",
						"local_addr":  info.LocalAddr,
						"local_port":  info.LocalPort,
						"remote_addr": info.RemoteAddr,
						"remote_port": info.RemotePort,
						"status":      info.Status,
						"pid":         info.PID,
						"type":        conn.Type,
					},
				}
				c.emitEvent(event)
			}
		}
	}

	// Check for closed connections
	for key, info := range c.knownConns {
		if !currentConns[key] {
			delete(c.knownConns, key)

			// Only emit for previously established connections
			if info.Status == "ESTABLISHED" {
				event := Event{
					Type:      EventTypeNetwork,
					Timestamp: time.Now(),
					Severity:  SeverityInfo,
					Data: map[string]interface{}{
						"action":      "disconnected",
						"local_addr":  info.LocalAddr,
						"local_port":  info.LocalPort,
						"remote_addr": info.RemoteAddr,
						"remote_port": info.RemotePort,
						"pid":         info.PID,
					},
				}
				c.emitEvent(event)
			}
		}
	}
}

func (c *NetworkCollector) connKey(conn psutilnet.ConnectionStat) string {
	return fmt.Sprintf("%s:%d-%s:%d-%d",
		conn.Laddr.IP, conn.Laddr.Port,
		conn.Raddr.IP, conn.Raddr.Port,
		conn.Pid,
	)
}

func (c *NetworkCollector) toConnInfo(conn psutilnet.ConnectionStat) connInfo {
	return connInfo{
		LocalAddr:  conn.Laddr.IP,
		LocalPort:  conn.Laddr.Port,
		RemoteAddr: conn.Raddr.IP,
		RemotePort: conn.Raddr.Port,
		Status:     conn.Status,
		PID:        conn.Pid,
	}
}

func (c *NetworkCollector) determineSeverity(info connInfo) string {
	// Check suspicious ports
	if reason, suspicious := c.suspiciousPorts[info.RemotePort]; suspicious {
		c.logger.Warn("Suspicious port connection",
			zap.Uint32("port", info.RemotePort),
			zap.String("reason", reason),
		)
		return SeverityHigh
	}

	if reason, suspicious := c.suspiciousPorts[info.LocalPort]; suspicious {
		if info.Status == "LISTEN" {
			c.logger.Warn("Suspicious listening port",
				zap.Uint32("port", info.LocalPort),
				zap.String("reason", reason),
			)
			return SeverityHigh
		}
	}

	// Check for external connections
	if c.isExternalIP(info.RemoteAddr) {
		return SeverityMedium
	}

	return SeverityLow
}

func (c *NetworkCollector) isExternalIP(ipStr string) bool {
	if ipStr == "" || ipStr == "127.0.0.1" || ipStr == "::1" {
		return false
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check for private IP ranges
	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"::1/128",
		"fe80::/10",
	}

	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return false
		}
	}

	return true
}

func (c *NetworkCollector) emitEvent(event Event) {
	select {
	case c.events <- event:
	default:
		c.logger.Warn("Event channel full, dropping event")
	}
}
