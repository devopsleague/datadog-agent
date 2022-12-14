// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package sbom

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// TrivyCollector uses trivy to generate a SBOM
type TrivyCollector struct{}

// ScanRootfs generates a SBOM from a filesystem
func (c *TrivyCollector) ScanRootfs(ctx context.Context, root string) (*types.Report, error) {
	reportFlagGroup := flag.NewReportFlagGroup()
	fsFlags := &flag.Flags{
		ReportFlagGroup: reportFlagGroup,
		ScanFlagGroup:   flag.NewScanFlagGroup()}
	globalFlags := flag.NewGlobalFlagGroup()

	opts, err := fsFlags.ToOptions("", []string{root}, globalFlags, os.Stdout)
	if err != nil {
		return nil, err
	}

	opts.Format = "table"
	opts.Timeout = 60 * time.Second
	opts.ListAllPkgs = true

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	defer func() {
		if errors.Is(err, context.DeadlineExceeded) {
			log.Warnf("increase --timeout value")
		}
	}()

	runner, err := artifact.NewRunner(ctx, opts)
	if err != nil {
		if errors.Is(err, artifact.SkipScan) {
			return nil, nil
		}
		return nil, fmt.Errorf("init error: %w", err)
	}
	defer runner.Close(ctx)

	report, err := runner.ScanRootfs(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("rootfs scan error: %w", err)
	}

	report, err = runner.Filter(ctx, opts, report)
	if err != nil {
		return nil, fmt.Errorf("filter error: %w", err)
	}

	if err = runner.Report(opts, report); err != nil {
		return nil, fmt.Errorf("report error: %w", err)
	}

	return &report, err
}

// NewTrivyCollector returns a new trivy SBOM collector
func NewTrivyCollector() *TrivyCollector {
	return &TrivyCollector{}
}
