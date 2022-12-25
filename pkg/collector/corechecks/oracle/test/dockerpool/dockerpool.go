// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.
package dockerpool

import (
	"errors"
	"fmt"
	"time"

	_ "github.com/godror/godror"
	"github.com/jmoiron/sqlx"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/sirupsen/logrus"
)

// TODO: Dockerpool should likely be an interface for future integrations to follow.

type OraclePoolConfig struct {
	// DbName is the name of the database in the pool.
	DbName string
	// Version of Oracle.
	Version string
	// MigrationsPath is the path to migrations to run.
	MigrationsPath string
	// Expiration sets the max amount of time to try and create an Oracle pool before exiting.
	Expiration uint
}

// TODO: This implementaton should be a bit more flexible to customization. Ignoring now for POC.
func CreateOraclePool(cfg *OraclePoolConfig) (*sqlx.DB, func(), error) {
	if cfg == nil {
		return nil, nil, errors.New("please configure this oracle docker pool")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		logrus.Fatalf("Failed to connect to docker: %s", err)
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "gvenzl/oracle-xe",
		Tag:        "latest",
		Env: []string{
			"ORACLE_PASSWORD=password",
		},
	}, func(config *docker.HostConfig) {
		config.AutoRemove = true
		config.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		logrus.Fatalf("Could not start resource: %s", err)
	}

	databaseUrl := fmt.Sprintf("%s/%s@127.0.0.1:1521/%s", "system", "password", cfg.DbName)

	logrus.Info("Connecting to database:", databaseUrl)

	// Hard kill the container
	if err := resource.Expire(cfg.Expiration); err != nil {
		logrus.Fatalf("Failed to set resource expiration: %s", err)
	}

	logrus.Infof("RESOURCE: container=%+v image=%s", resource.Container, resource.Container.Image)

	var db *sqlx.DB

	// Exponential backoff-retry, our app in the container might not be ready to accept connections yet
	pool.MaxWait = time.Duration(cfg.Expiration) * time.Second
	if err = pool.Retry(func() error {
		db, err = sqlx.Open("godror", databaseUrl)
		if err != nil {
			fmt.Println("Some error", err)
			return err
		}
		return db.Ping()
	}); err != nil {
		logrus.Fatalf("Failed to connect to docker after %d seconds | err=[%s]", cfg.Expiration, err)
	}

	teardown := func() {
		logrus.Info("Tearing down oracle docker pool.")
		if err := pool.Purge(resource); err != nil {
			logrus.Errorf("Failed to purge oracle pool resource: %s", err)
		}
	}

	return db, teardown, nil
}

// TODO: This implementaton should be a bit more flexible to customization. Ignoring now for POC.
func Test() {
	databaseUrl := fmt.Sprintf("%s/%s@127.0.0.1:1521/%s", "system", "password", "XE")

	logrus.Info("Connecting to database:", databaseUrl)

	db, err := sqlx.Open("godror", databaseUrl)
	if err != nil {
		fmt.Println("Some error", err)
	}

	type Test struct {
		PDB_ID int `db:"PDB_ID"`
	}

	var tests []Test
	err = db.Select(&tests, "SELECT * FROM dba_pdbs")
	if err != nil {
		fmt.Println("ERROR:", err)
	}
	fmt.Println("TEST", tests)
}
