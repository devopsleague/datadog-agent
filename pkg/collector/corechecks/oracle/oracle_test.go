// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.
package oracle

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/DataDog/datadog-agent/pkg/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/oracle/test/dockerpool"
)

func TestBasic(t *testing.T) {
	chk := Check{}

	// language=yaml
	rawInstanceConfig := []byte(`
`)

	dockerpool.Test()

	err := chk.Configure(integration.FakeConfigHash, rawInstanceConfig, []byte(``), "oracle_test")
	assert.Error(t, err)
	// dockerpool.CreateOraclePool(&dockerpool.OraclePoolConfig{
	// 	DbName:     "XE",
	// 	Expiration: 30,
	// })

}
