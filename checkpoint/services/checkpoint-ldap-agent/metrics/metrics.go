// Package metrics provides Prometheus instrumentation for checkpoint-ldap-agent.
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Metrics holds all Prometheus counters, histograms, and gauges for the agent.
type Metrics struct {
	// BindRequests counts LDAP bind requests by result label:
	// "success", "invalid_credentials", "error"
	BindRequests *prometheus.CounterVec

	// SearchRequests counts LDAP search requests by result label:
	// "success", "error"
	SearchRequests *prometheus.CounterVec

	// BindLatency measures the duration of LDAP bind operations.
	BindLatency prometheus.Histogram

	// SearchLatency measures the duration of LDAP search operations.
	SearchLatency prometheus.Histogram

	// GRPCConnected is 1 when the gRPC connection to checkpoint-core is active.
	GRPCConnected prometheus.Gauge

	// HeartbeatsSent counts total heartbeats sent to checkpoint-core.
	HeartbeatsSent prometheus.Counter
}

// NewMetrics registers and returns all Prometheus metrics for the agent.
func NewMetrics() *Metrics {
	return &Metrics{
		BindRequests: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "checkpoint_ldap_agent_bind_requests_total",
				Help: "Total number of LDAP bind requests processed by the agent.",
			},
			[]string{"result"}, // success | invalid_credentials | error
		),

		SearchRequests: promauto.NewCounterVec(
			prometheus.CounterOpts{
				Name: "checkpoint_ldap_agent_search_requests_total",
				Help: "Total number of LDAP search requests processed by the agent.",
			},
			[]string{"result"}, // success | error
		),

		BindLatency: promauto.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "checkpoint_ldap_agent_bind_duration_seconds",
				Help:    "Histogram of LDAP bind request durations in seconds.",
				Buckets: prometheus.DefBuckets,
			},
		),

		SearchLatency: promauto.NewHistogram(
			prometheus.HistogramOpts{
				Name:    "checkpoint_ldap_agent_search_duration_seconds",
				Help:    "Histogram of LDAP search request durations in seconds.",
				Buckets: prometheus.DefBuckets,
			},
		),

		GRPCConnected: promauto.NewGauge(
			prometheus.GaugeOpts{
				Name: "checkpoint_ldap_agent_grpc_connected",
				Help: "1 if the gRPC connection to checkpoint-core is active, 0 otherwise.",
			},
		),

		HeartbeatsSent: promauto.NewCounter(
			prometheus.CounterOpts{
				Name: "checkpoint_ldap_agent_heartbeats_total",
				Help: "Total number of heartbeats successfully sent to checkpoint-core.",
			},
		),
	}
}
