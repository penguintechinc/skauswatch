// checkpoint-ldap-agent — remote LDAP presence for the Checkpoint sub-module.
// Runs in a customer VPC, bridges local LDAP clients to checkpoint-core via gRPC.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"

	grpcclient "github.com/penguintechinc/skauswatch/checkpoint/ldap-agent/grpc"
	ldapagent "github.com/penguintechinc/skauswatch/checkpoint/ldap-agent/ldap"
	"github.com/penguintechinc/skauswatch/checkpoint/ldap-agent/metrics"
	restclient "github.com/penguintechinc/skauswatch/checkpoint/ldap-agent/rest"
)

func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func main() {
	healthcheck := flag.Bool("healthcheck", false, "perform health check and exit")
	flag.Parse()

	// Health check mode: dial LDAP port and exit
	if *healthcheck {
		ldapPort := getEnv("LDAP_PORT", "389")
		conn, err := net.DialTimeout("tcp", "localhost:"+ldapPort, 3*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "health check failed: %v\n", err)
			os.Exit(1)
		}
		conn.Close()
		os.Exit(0)
	}

	// Required config
	agentID := os.Getenv("AGENT_ID")
	if agentID == "" {
		fmt.Fprintln(os.Stderr, "AGENT_ID environment variable is required")
		os.Exit(1)
	}

	// Optional config with defaults
	grpcHost := getEnv("CHECKPOINT_GRPC_HOST", "checkpoint-core")
	grpcPort := getEnv("CHECKPOINT_GRPC_PORT", "50051")
	coreURL := getEnv("SKAUSWATCH_CORE_URL", "http://skauswatch-core:8080")
	ldapPortStr := getEnv("LDAP_PORT", "389")
	metricsPortStr := getEnv("METRICS_PORT", "9090")
	baseDN := getEnv("LDAP_BASE_DN", "dc=skauswatch,dc=app")
	siteName := getEnv("AGENT_SITE_NAME", "default")

	ldapPort, err := strconv.Atoi(ldapPortStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid LDAP_PORT: %v\n", err)
		os.Exit(1)
	}
	metricsPort, err := strconv.Atoi(metricsPortStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid METRICS_PORT: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	logger, err := zap.NewProduction()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer logger.Sync() //nolint:errcheck

	logger.Info("starting checkpoint-ldap-agent",
		zap.String("agent_id", agentID),
		zap.String("site_name", siteName),
		zap.String("grpc_host", grpcHost),
		zap.String("grpc_port", grpcPort),
		zap.Int("ldap_port", ldapPort),
	)

	// Initialize metrics
	m := metrics.NewMetrics()

	// Initialize gRPC client
	grpcClient, err := grpcclient.NewClient(grpcHost, grpcPort, agentID, logger)
	if err != nil {
		logger.Fatal("failed to initialize gRPC client", zap.Error(err))
	}
	defer grpcClient.Close() //nolint:errcheck
	m.GRPCConnected.Set(1)

	// Initialize REST fallback client
	restClient := restclient.NewFallbackClient(coreURL, logger)

	// Initialize LDAP server
	ldapServer := ldapagent.NewServer(grpcClient, restClient, baseDN, agentID, logger, m)

	// Register agent with checkpoint-core
	hostname, _ := os.Hostname()
	if err := grpcClient.Register(agentID, hostname, "1.0.0", siteName); err != nil {
		logger.Warn("failed to register agent with checkpoint-core (will retry via heartbeat)", zap.Error(err))
	} else {
		logger.Info("agent registered with checkpoint-core")
	}

	// Start heartbeat goroutine
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := grpcClient.Heartbeat(agentID); err != nil {
					logger.Warn("heartbeat failed", zap.Error(err))
					m.GRPCConnected.Set(0)
				} else {
					m.GRPCConnected.Set(1)
					m.HeartbeatsSent.Inc()
				}
			}
		}
	}()

	// Start LDAP server
	if err := ldapServer.Start(ldapPort); err != nil {
		logger.Fatal("failed to start LDAP server", zap.Error(err))
	}
	logger.Info("LDAP server started", zap.Int("port", ldapPort))

	// Start Prometheus metrics server
	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	metricsMux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})
	metricsServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", metricsPort),
		Handler:      metricsMux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	go func() {
		logger.Info("metrics server started", zap.Int("port", metricsPort))
		if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics server error", zap.Error(err))
		}
	}()

	// Block until signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigCh
	logger.Info("received shutdown signal", zap.String("signal", sig.String()))

	// Graceful shutdown
	cancel() // stop heartbeat

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	if err := metricsServer.Shutdown(shutdownCtx); err != nil {
		logger.Warn("metrics server shutdown error", zap.Error(err))
	}

	ldapServer.Stop()
	logger.Info("checkpoint-ldap-agent stopped")
}
