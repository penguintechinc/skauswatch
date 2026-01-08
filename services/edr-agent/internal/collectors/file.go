package collectors

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.uber.org/zap"
)

// FileCollector monitors file system changes
type FileCollector struct {
	logger       *zap.Logger
	events       chan Event
	stopChan     chan struct{}
	running      bool
	mu           sync.Mutex
	watchPaths   []string
	fileHashes   map[string]string
	pollInterval time.Duration
}

// NewFileCollector creates a new file collector
func NewFileCollector(logger *zap.Logger) (*FileCollector, error) {
	// Default paths to watch
	watchPaths := []string{
		"/etc",
		"/usr/bin",
		"/usr/sbin",
	}

	// Windows paths
	if _, err := os.Stat("C:\\Windows"); err == nil {
		watchPaths = []string{
			"C:\\Windows\\System32",
			"C:\\Windows\\SysWOW64",
			"C:\\Users",
		}
	}

	return &FileCollector{
		logger:       logger,
		events:       make(chan Event, 1000),
		stopChan:     make(chan struct{}),
		watchPaths:   watchPaths,
		fileHashes:   make(map[string]string),
		pollInterval: 30 * time.Second,
	}, nil
}

// Name returns the collector name
func (c *FileCollector) Name() string {
	return "file"
}

// Start begins collecting file events
func (c *FileCollector) Start() error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return nil
	}
	c.running = true
	c.mu.Unlock()

	// Initialize file hashes
	c.initFileHashes()

	go c.collectLoop()
	c.logger.Info("File collector started",
		zap.Strings("paths", c.watchPaths),
	)
	return nil
}

// Stop stops the collector
func (c *FileCollector) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	close(c.stopChan)
	c.running = false
	c.logger.Info("File collector stopped")
	return nil
}

// Events returns the event channel
func (c *FileCollector) Events() <-chan Event {
	return c.events
}

func (c *FileCollector) initFileHashes() {
	for _, watchPath := range c.watchPaths {
		c.scanDirectory(watchPath, true)
	}
	c.logger.Info("File baseline initialized",
		zap.Int("files", len(c.fileHashes)),
	)
}

func (c *FileCollector) collectLoop() {
	ticker := time.NewTicker(c.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopChan:
			return
		case <-ticker.C:
			c.checkFiles()
		}
	}
}

func (c *FileCollector) checkFiles() {
	currentFiles := make(map[string]string)

	for _, watchPath := range c.watchPaths {
		c.scanDirectory(watchPath, false)
	}

	// Check for deleted files
	for path, oldHash := range c.fileHashes {
		if _, exists := currentFiles[path]; !exists {
			if _, err := os.Stat(path); os.IsNotExist(err) {
				delete(c.fileHashes, path)

				event := Event{
					Type:      EventTypeFile,
					Timestamp: time.Now(),
					Severity:  c.determineSeverity(path, "deleted"),
					Data: map[string]interface{}{
						"action":   "deleted",
						"path":     path,
						"old_hash": oldHash,
					},
				}
				c.emitEvent(event)
			}
		}
	}
}

func (c *FileCollector) scanDirectory(dir string, init bool) {
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if info.IsDir() {
			return nil
		}

		// Skip files larger than 10MB for performance
		if info.Size() > 10*1024*1024 {
			return nil
		}

		hash, err := c.hashFile(path)
		if err != nil {
			return nil
		}

		if init {
			c.fileHashes[path] = hash
			return nil
		}

		oldHash, exists := c.fileHashes[path]

		if !exists {
			// New file
			c.fileHashes[path] = hash
			event := Event{
				Type:      EventTypeFile,
				Timestamp: time.Now(),
				Severity:  c.determineSeverity(path, "created"),
				Data: map[string]interface{}{
					"action": "created",
					"path":   path,
					"hash":   hash,
					"size":   info.Size(),
					"mode":   info.Mode().String(),
				},
			}
			c.emitEvent(event)
		} else if oldHash != hash {
			// Modified file
			c.fileHashes[path] = hash
			event := Event{
				Type:      EventTypeFile,
				Timestamp: time.Now(),
				Severity:  c.determineSeverity(path, "modified"),
				Data: map[string]interface{}{
					"action":   "modified",
					"path":     path,
					"old_hash": oldHash,
					"new_hash": hash,
					"size":     info.Size(),
				},
			}
			c.emitEvent(event)
		}

		return nil
	})
}

func (c *FileCollector) hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func (c *FileCollector) determineSeverity(path, action string) string {
	// Critical system paths
	criticalPaths := []string{
		"/etc/passwd", "/etc/shadow", "/etc/sudoers",
		"C:\\Windows\\System32\\config",
	}

	for _, critical := range criticalPaths {
		if path == critical {
			return SeverityCritical
		}
	}

	// Executable modifications
	ext := filepath.Ext(path)
	execExts := []string{".exe", ".dll", ".so", ".sh", ".py", ".ps1"}
	for _, execExt := range execExts {
		if ext == execExt {
			return SeverityHigh
		}
	}

	// Config file modifications
	if filepath.Dir(path) == "/etc" || ext == ".conf" || ext == ".cfg" {
		return SeverityMedium
	}

	return SeverityLow
}

func (c *FileCollector) emitEvent(event Event) {
	select {
	case c.events <- event:
	default:
		c.logger.Warn("Event channel full, dropping event")
	}
}
