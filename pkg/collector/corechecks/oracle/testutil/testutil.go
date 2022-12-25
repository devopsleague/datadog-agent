// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package testutil

import (
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/ory/dockertest/docker"
	"github.com/sirupsen/logrus"

	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/oracle/testutil/dockerpool"
)

// CreateOraclePool creates an Oracle docker pool used for testing.
func CreateOraclePool(dbName string, port int, expiration uint) (*sqlx.DB, dockerpool.TeardownFunc) {
	portStr := fmt.Sprintf("%d/tcp", port)

	// TODO: Define users, add migrations
	pool, resource, teardown := dockerpool.CreatePool(&dockerpool.PoolConfig{
		Repository: "gvenzl/oracle-xe",
		ImageTag:   "latest",
		DockerHostConfig: &docker.HostConfig{
			AutoRemove:    true,
			RestartPolicy: docker.RestartPolicy{Name: "no"},
		},
	}, dockerpool.OptionEnvs("ORACLE_PASSWORD=password"), dockerpool.OptionalExposedPorts(portStr))

	databaseUrl := fmt.Sprintf("%s/%s@localhost:%s/%s", "system", "password", resource.GetPort(portStr), dbName)

	// Hard kill the container
	if err := resource.Expire(expiration); err != nil {
		logrus.Fatalf("Failed to set resource expiration: %s", err)
	}

	var db *sqlx.DB

	// Exponential backoff-retry, our app in the container might not be ready to accept connections yet
	pool.MaxWait = time.Duration(expiration) * time.Second
	if err := pool.Retry(func() error {
		oracleDB, err := sqlx.Open("godror", databaseUrl)
		if err != nil {
			return err
		}
		db = oracleDB
		return oracleDB.Ping()
	}); err != nil {
		logrus.Fatalf("Failed to connect to docker after %d seconds | err=[%s]", expiration, err)
	}

	return db, teardown
}
