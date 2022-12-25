// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package config

import (
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/DataDog/datadog-agent/pkg/autodiscovery/integration"
)

// InitConfig is used to deserialize integration init config.
type InitConfig struct {
	GlobalCustomQueries []MetricConfig `yaml:"global_custom_metrics"`
	Service             string         `yaml:"service"`
}

// InstanceConfig is used to deserialize integration instance config.
type InstanceConfig struct {
	Server                 string `yaml:"server"`
	ServiceName            string `yaml:"service_name"`
	Protocol               string `yaml:"protocol"`
	Username               string `yaml:"username"`
	Password               string `yaml:"password"`
	JdbcDriverPath         string `yaml:"jdbc_driver_path"`
	JdbcTruststorePath     string `yaml:"jdbc_truststore_path"`
	JdbcTruststoreType     string `yaml:"jdbc_truststore_type"`
	JdbcTruststorePassword string `yaml:"jdbc_truststore_password"`
}

// CheckConfig holds the config needed for an integration instance to run.
type CheckConfig struct {
	InitConfig
	InstanceConfig
}

// ToString returns a string representation of the CheckConfig without sensitive information.
func (c *CheckConfig) ToString() string {
	return fmt.Sprintf(`CheckConfig:
GlobalCustomQueries: '%+v'
Service: '%s'
Server: '%s'
ServiceName: '%s'
Protocol: '%s'
JDBC Driver Path: '%s'
JDBC Truststore Path: '%s'
JDBC Truststore Type: '%s'
`, c.GlobalCustomQueries, c.Service, c.Server, c.ServiceName, c.Protocol, c.JdbcDriverPath, c.JdbcTruststorePath, c.JdbcTruststoreType)
}

// NewCheckConfig builds a new check config.
func NewCheckConfig(rawInstance integration.Data, rawInitConfig integration.Data) (*CheckConfig, error) {
	instance := InstanceConfig{}
	initCfg := InitConfig{}

	// REMOVE ME: Testing...
	fmt.Println("Oracle rawInstance", rawInstance)
	fmt.Println("Oracle rawInitConfig", rawInitConfig)

	if err := yaml.Unmarshal(rawInstance, &instance); err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(rawInitConfig, &initCfg); err != nil {
		return nil, err
	}

	fmt.Println("Oracle Instance", instance)
	fmt.Println("Oracle InitConfig", initCfg)

	c := &CheckConfig{}
	return c, nil
}
