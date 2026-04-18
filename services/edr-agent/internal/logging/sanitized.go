// Package logging provides a sanitized logger that wraps zap.Logger and
// automatically redacts sensitive field values before writing log entries.
// This mirrors the interface of go-common SanitizedLogger from
// github.com/penguintechinc/penguin-libs/packages/go-common/logging.
package logging

import (
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// sensitiveKeys is the set of field key substrings that trigger redaction.
var sensitiveKeys = map[string]bool{
	"password":      true,
	"token":         true,
	"api_key":       true,
	"apikey":        true,
	"secret":        true,
	"credential":    true,
	"authorization": true,
	"access_token":  true,
	"refresh_token": true,
	"session_id":    true,
}

// SanitizedLogger wraps *zap.Logger and sanitizes field values before
// passing them to the underlying logger.  All method signatures are
// identical to *zap.Logger so call sites require no changes.
type SanitizedLogger struct {
	*zap.Logger
}

// NewSanitizedLogger creates a SanitizedLogger with production JSON encoding
// writing to stdout, named with the provided service name.
func NewSanitizedLogger(name string) (*SanitizedLogger, error) {
	cfg := zap.NewProductionConfig()
	cfg.EncoderConfig.TimeKey = "timestamp"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	logger, err := cfg.Build()
	if err != nil {
		return nil, err
	}

	return &SanitizedLogger{Logger: logger.Named(name)}, nil
}

// Debug logs at DEBUG level after sanitizing fields.
func (l *SanitizedLogger) Debug(msg string, fields ...zap.Field) {
	l.Logger.Debug(msg, sanitizeFields(fields)...)
}

// Info logs at INFO level after sanitizing fields.
func (l *SanitizedLogger) Info(msg string, fields ...zap.Field) {
	l.Logger.Info(msg, sanitizeFields(fields)...)
}

// Warn logs at WARN level after sanitizing fields.
func (l *SanitizedLogger) Warn(msg string, fields ...zap.Field) {
	l.Logger.Warn(msg, sanitizeFields(fields)...)
}

// Error logs at ERROR level after sanitizing fields.
func (l *SanitizedLogger) Error(msg string, fields ...zap.Field) {
	l.Logger.Error(msg, sanitizeFields(fields)...)
}

// sanitizeFields returns a copy of fields with sensitive values replaced by
// the literal string "[REDACTED]".
func sanitizeFields(fields []zap.Field) []zap.Field {
	result := make([]zap.Field, len(fields))
	for i, f := range fields {
		if isSensitive(f.Key) {
			result[i] = zap.String(f.Key, "[REDACTED]")
		} else {
			result[i] = f
		}
	}
	return result
}

// isSensitive reports whether the given key contains a sensitive substring.
func isSensitive(key string) bool {
	lower := strings.ToLower(key)
	for sensitive := range sensitiveKeys {
		if strings.Contains(lower, sensitive) {
			return true
		}
	}
	return false
}
