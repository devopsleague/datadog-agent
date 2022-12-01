// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

package containerimage

import (
	"errors"
	"time"

	yaml "gopkg.in/yaml.v2"

	"github.com/DataDog/datadog-agent/pkg/autodiscovery/integration"
	"github.com/DataDog/datadog-agent/pkg/collector/check"
	core "github.com/DataDog/datadog-agent/pkg/collector/corechecks"
	ddConfig "github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/workloadmeta"
)

const (
	checkName = "container_image"
)

func init() {
	core.RegisterCheck(checkName, CheckFactory)
}

// Config holds the container_image check configuration
type Config struct {
	chunkSize                  int `yaml:"chunk_size"`
	newImagesMaxLatencySeconds int `yaml:"new_images_max_latency_seconds"`
	// periodicRefreshSeconds     int `yaml:"periodic_refresh_seconds"`
}

func (c *Config) Parse(data []byte) error {
	return yaml.Unmarshal(data, c)
}

// Check reports container images
type Check struct {
	core.CheckBase
	workloadmetaStore workloadmeta.Store
	instance          *Config
	processor         *processor
	stopCh            chan struct{}
}

// CheckFactory registers the container_image check
func CheckFactory() check.Check {
	return &Check{
		CheckBase:         core.NewCheckBase(checkName),
		workloadmetaStore: workloadmeta.GetGlobalStore(),
		instance:          &Config{},
		stopCh:            make(chan struct{}),
	}
}

// Configure parses the check configuration and initializes the container_image check
func (c *Check) Configure(config, initConfig integration.Data, source string) error {
	if !ddConfig.Datadog.GetBool("container_image.enabled") {
		return errors.New("collection of container images is disabled")
	}

	if err := c.CommonConfigure(initConfig, config, source); err != nil {
		return err
	}

	if err := c.instance.Parse(config); err != nil {
		return err
	}

	sender, err := c.GetSender()
	if err != nil {
		return err
	}

	c.processor = newProcessor(sender, c.instance.chunkSize, time.Duration(c.instance.newImagesMaxLatencySeconds)*time.Second)

	return nil
}

// Run starts the container_image check
func (c *Check) Run() error {
	log.Infof("Starting long-running check %q", c.ID())
	defer log.Infof("Shutting down long-running check %q", c.ID())

	imgEventsCh := c.workloadmetaStore.Subscribe(
		checkName,
		workloadmeta.NormalPriority,
		workloadmeta.NewFilter(
			[]workloadmeta.Kind{workloadmeta.KindContainerImageMetadata},
			workloadmeta.SourceAll,    // TODO: check
			workloadmeta.EventTypeAll, // TODO: Do we have image deletion / are we interested in deletion ?
		),
	)

	for {
		select {
		case eventBundle := <-imgEventsCh:
			c.processor.processEvents(eventBundle)
		case <-c.stopCh:
			c.processor.stop()
			return nil
		}
	}
}

// Stop stops the container_image check
func (c *Check) Stop() {
	close(c.stopCh)
}

// Interval returns 0. It makes container_image a long-running check
func (c *Check) Interval() time.Duration {
	return 0
}
