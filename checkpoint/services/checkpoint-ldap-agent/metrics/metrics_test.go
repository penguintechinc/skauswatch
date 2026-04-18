package metrics

import (
	"testing"
)

func TestNewMetrics_NotNil(t *testing.T) {
	m := NewMetrics()

	// Test that all fields are non-nil
	if m.BindRequests == nil {
		t.Error("BindRequests is nil")
	}
	if m.SearchRequests == nil {
		t.Error("SearchRequests is nil")
	}
	if m.BindLatency == nil {
		t.Error("BindLatency is nil")
	}
	if m.SearchLatency == nil {
		t.Error("SearchLatency is nil")
	}
	if m.GRPCConnected == nil {
		t.Error("GRPCConnected is nil")
	}
	if m.HeartbeatsSent == nil {
		t.Error("HeartbeatsSent is nil")
	}
}

func TestNewMetrics_CanRecordMetrics(t *testing.T) {
	m := NewMetrics()

	// Test that we can record metrics without panicking
	m.BindRequests.WithLabelValues("success").Inc()
	m.SearchRequests.WithLabelValues("error").Inc()
	m.BindLatency.Observe(0.5)
	m.SearchLatency.Observe(1.2)
	m.GRPCConnected.Set(1)
	m.HeartbeatsSent.Inc()

	// If we get here without panicking, metrics work
	t.Log("All metrics recorded successfully")
}

func TestNewMetrics_CounterVecLabels(t *testing.T) {
	m := NewMetrics()

	// Test bind request labels
	bindLabels := []string{"success", "invalid_credentials", "error"}
	for _, label := range bindLabels {
		m.BindRequests.WithLabelValues(label).Inc()
	}

	// Test search request labels
	searchLabels := []string{"success", "error"}
	for _, label := range searchLabels {
		m.SearchRequests.WithLabelValues(label).Inc()
	}

	// If we get here without panicking, labels work correctly
	t.Log("All counter vec labels handled correctly")
}

func TestNewMetrics_MultipleInstances(t *testing.T) {
	// Creating multiple instances should not panic or cause issues
	m1 := NewMetrics()
	m2 := NewMetrics()

	if m1 == nil || m2 == nil {
		t.Fatal("metrics instances are nil")
	}

	// Both instances should be usable
	m1.BindRequests.WithLabelValues("success").Inc()
	m2.BindRequests.WithLabelValues("success").Inc()

	t.Log("Multiple metric instances created and used successfully")
}

func TestNewMetrics_GaugeOperations(t *testing.T) {
	m := NewMetrics()

	// Test gauge set and increment/decrement
	m.GRPCConnected.Set(1)
	m.GRPCConnected.Set(0)
	m.GRPCConnected.Inc()
	m.GRPCConnected.Dec()

	t.Log("Gauge operations completed successfully")
}

func TestNewMetrics_HistogramObservations(t *testing.T) {
	m := NewMetrics()

	// Test histogram with various durations
	observations := []float64{0.001, 0.01, 0.1, 0.5, 1.0, 5.0, 10.0}
	for _, obs := range observations {
		m.BindLatency.Observe(obs)
		m.SearchLatency.Observe(obs)
	}

	t.Log("Histogram observations recorded successfully")
}

func TestNewMetrics_CounterIncrement(t *testing.T) {
	m := NewMetrics()

	// Test counter multiple increments
	for i := 0; i < 10; i++ {
		m.HeartbeatsSent.Inc()
	}

	t.Log("Counter increments completed successfully")
}
