package dltreceiver

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
)

var TypeStr = component.MustNewType("dlt")

type Config struct {
	DaemonAddress string          `mapstructure:"daemon_address"`
	DaemonPort    int             `mapstructure:"daemon_port"`
	Extractors    []ExtractorRule `mapstructure:"extractors"`
}

type ExtractorRule struct {
	Pattern   string `mapstructure:"pattern"`
	FieldName string `mapstructure:"field_name"`
}

func createDefaultConfig() component.Config {
	return &Config{
		DaemonAddress: "localhost",
		DaemonPort:    3490,
		Extractors:    []ExtractorRule{},
	}
}

func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		TypeStr,
		createDefaultConfig,
		receiver.WithLogs(createReceiver, component.StabilityLevelBeta))
}

func createReceiver(
	_ context.Context,
	set receiver.Settings,
	cfg component.Config,
	nextConsumer consumer.Logs,
) (receiver.Logs, error) {
	rCfg := cfg.(*Config)
	return &dltReceiver{
		config:       rCfg,
		nextConsumer: nextConsumer,
		logger:       set.Logger,
	}, nil
}
