// Copyright Elven Observability
// SPDX-License-Identifier: Apache-2.0

package elvenprivacyprocessor

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/processor"
	"go.opentelemetry.io/collector/processor/processorhelper"
)

// NewFactory registers the Elven privacy policy for all three OTLP signals.
func NewFactory() processor.Factory {
	return processor.NewFactory(component.MustNewType("elven_privacy"),
		func() component.Config { return defaultConfig() },
		processor.WithLogs(createLogs, component.StabilityLevelBeta),
		processor.WithMetrics(createMetrics, component.StabilityLevelBeta),
		processor.WithTraces(createTraces, component.StabilityLevelBeta))
}

func createLogs(ctx context.Context, settings processor.Settings, config component.Config, next consumer.Logs) (processor.Logs, error) {
	c := config.(*Config)
	if err := c.Validate(); err != nil {
		return nil, err
	}
	p := &privacyProcessor{config: *c}
	return processorhelper.NewLogs(ctx, settings, config, next, p.processLogs,
		processorhelper.WithCapabilities(consumer.Capabilities{MutatesData: true}))
}

func createMetrics(ctx context.Context, settings processor.Settings, config component.Config, next consumer.Metrics) (processor.Metrics, error) {
	c := config.(*Config)
	if err := c.Validate(); err != nil {
		return nil, err
	}
	p := &privacyProcessor{config: *c}
	return processorhelper.NewMetrics(ctx, settings, config, next, p.processMetrics,
		processorhelper.WithCapabilities(consumer.Capabilities{MutatesData: true}))
}

func createTraces(ctx context.Context, settings processor.Settings, config component.Config, next consumer.Traces) (processor.Traces, error) {
	c := config.(*Config)
	if err := c.Validate(); err != nil {
		return nil, err
	}
	p := &privacyProcessor{config: *c}
	return processorhelper.NewTraces(ctx, settings, config, next, p.processTraces,
		processorhelper.WithCapabilities(consumer.Capabilities{MutatesData: true}))
}
