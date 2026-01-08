// SkausWatch EDR Agent
// Endpoint Detection and Response agent for security monitoring
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/penguintech/skauswatch/edr-agent/internal/agent"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	cfgFile string
	logger  *zap.Logger
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "edr-agent",
		Short: "SkausWatch EDR Agent",
		Long: `SkausWatch EDR Agent - Endpoint Detection and Response

This agent monitors system activity, detects security threats,
and reports events to the SkausWatch Manager service.`,
		Run: runAgent,
	}

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: /etc/skauswatch/edr-agent.yaml)")
	rootCmd.PersistentFlags().String("manager-url", "https://manager:5000", "SkausWatch Manager API URL")
	rootCmd.PersistentFlags().String("api-key", "", "API key for authentication")
	rootCmd.PersistentFlags().String("agent-id", "", "Unique agent identifier (auto-generated if empty)")
	rootCmd.PersistentFlags().Bool("debug", false, "Enable debug logging")

	viper.BindPFlag("manager_url", rootCmd.PersistentFlags().Lookup("manager-url"))
	viper.BindPFlag("api_key", rootCmd.PersistentFlags().Lookup("api-key"))
	viper.BindPFlag("agent_id", rootCmd.PersistentFlags().Lookup("agent-id"))
	viper.BindPFlag("debug", rootCmd.PersistentFlags().Lookup("debug"))

	cobra.OnInitialize(initConfig)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("edr-agent")
		viper.SetConfigType("yaml")
		viper.AddConfigPath("/etc/skauswatch")
		viper.AddConfigPath(".")
	}

	viper.SetEnvPrefix("EDR")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		// Config file not found is OK, use defaults
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fmt.Printf("Error reading config: %v\n", err)
		}
	}

	// Initialize logger
	var err error
	if viper.GetBool("debug") {
		logger, err = zap.NewDevelopment()
	} else {
		logger, err = zap.NewProduction()
	}
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
}

func runAgent(cmd *cobra.Command, args []string) {
	defer logger.Sync()

	logger.Info("Starting SkausWatch EDR Agent",
		zap.String("version", "1.0.0"),
	)

	// Build configuration
	config := agent.Config{
		ManagerURL:      viper.GetString("manager_url"),
		APIKey:          viper.GetString("api_key"),
		AgentID:         viper.GetString("agent_id"),
		HeartbeatSecs:   viper.GetInt("heartbeat_interval"),
		EventBufferSize: viper.GetInt("event_buffer_size"),
		Collectors: agent.CollectorConfig{
			ProcessEnabled:  viper.GetBool("collectors.process.enabled"),
			FileEnabled:     viper.GetBool("collectors.file.enabled"),
			NetworkEnabled:  viper.GetBool("collectors.network.enabled"),
			RegistryEnabled: viper.GetBool("collectors.registry.enabled"),
		},
	}

	// Set defaults
	if config.HeartbeatSecs == 0 {
		config.HeartbeatSecs = 60
	}
	if config.EventBufferSize == 0 {
		config.EventBufferSize = 1000
	}

	// Create agent
	edrAgent, err := agent.New(config, logger)
	if err != nil {
		logger.Fatal("Failed to create agent", zap.Error(err))
	}

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		logger.Info("Received shutdown signal", zap.String("signal", sig.String()))
		cancel()
	}()

	// Run agent
	if err := edrAgent.Run(ctx); err != nil {
		logger.Error("Agent error", zap.Error(err))
		os.Exit(1)
	}

	logger.Info("EDR Agent stopped")
}
