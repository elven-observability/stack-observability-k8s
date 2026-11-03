// Copyright Elven Observability
// SPDX-License-Identifier: Apache-2.0

package elvenprivacyprocessor

import "fmt"

// Config controls bounded, selective sanitization before persistent queues.
// It is a basic credential/PII policy, not a universal data-classification engine.
type Config struct {
	LogBodyMode        string `mapstructure:"log_body_mode"`
	PreserveSpanLinks  bool   `mapstructure:"preserve_span_links"`
	MaxDepth           int    `mapstructure:"max_depth"`
	MaxStringBytes     int    `mapstructure:"max_string_bytes"`
	MaxCollectionItems int    `mapstructure:"max_collection_items"`
}

func defaultConfig() *Config {
	return &Config{LogBodyMode: "selective", PreserveSpanLinks: true,
		MaxDepth: 24, MaxStringBytes: 262144, MaxCollectionItems: 4096}
}

func (c *Config) Validate() error {
	if c.LogBodyMode != "selective" && c.LogBodyMode != "strict" {
		return fmt.Errorf("log_body_mode must be selective or strict")
	}
	// Each nested AnyValue container adds multiple protobuf message levels.
	// Leave room for the OTLP resource/scope/record envelope under decoders'
	// usual recursion limit instead of emitting a batch they cannot consume.
	if c.MaxDepth < 1 || c.MaxDepth > 24 {
		return fmt.Errorf("max_depth must be between 1 and 24 for OTLP/protobuf interoperability")
	}
	if c.MaxStringBytes < 256 || c.MaxStringBytes > 1048576 {
		return fmt.Errorf("max_string_bytes must be between 256 and 1048576")
	}
	if c.MaxCollectionItems < 1 || c.MaxCollectionItems > 16384 {
		return fmt.Errorf("max_collection_items must be between 1 and 16384")
	}
	return nil
}
