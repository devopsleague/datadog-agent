// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package probe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/flag"
	trivyReport "github.com/aquasecurity/trivy/pkg/types"
	"github.com/hashicorp/golang-lru/v2/simplelru"
	"go.uber.org/atomic"

	coreconfig "github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/security/secl/model"
	"github.com/DataDog/datadog-agent/pkg/security/seclog"
	"github.com/DataDog/datadog-agent/pkg/security/utils"
)

// SBOMSource defines is the default log source for the SBOM events
const SBOMSource = "runtime-security-agent"

type Package struct {
	name    string
	version string
}

type SBOM struct {
	sync.RWMutex

	report trivyReport.Report
	files  map[string]*Package

	Host             string
	Source           string
	Service          string
	Tags             []string
	ContainerID      string
	ReferenceCounter *atomic.Uint64

	sbomResolver    *SBOMResolver
	shouldScan      bool
	rootCandidates  *simplelru.LRU[uint32, string]
	doNotSendBefore time.Time
	sent            bool
}

// NewSBOM returns a new empty instance of SBOM
func NewSBOM(r *SBOMResolver, process *model.ProcessCacheEntry) (*SBOM, error) {
	lru, err := simplelru.NewLRU(1000, func(key uint32, value string) {})
	if err != nil {
		return nil, fmt.Errorf("couldn't create new SBOM: %w", err)
	}
	lru.Add(process.Pid, utils.ProcRootPath(int32(process.Pid)))

	return &SBOM{
		files:            make(map[string]*Package),
		Host:             r.hostname,
		Source:           r.source,
		ContainerID:      process.ContainerID,
		ReferenceCounter: atomic.NewUint64(1),
		sbomResolver:     r,
		shouldScan:       true,
		rootCandidates:   lru,
		doNotSendBefore:  time.Now().Add(5 * time.Minute),
	}, nil
}

// resolveTags thread unsafe version of ResolveTags
func (s *SBOM) resolveTags() error {
	if len(s.Tags) >= 10 || len(s.ContainerID) == 0 {
		return nil
	}

	var err error
	s.Tags, err = s.sbomResolver.probe.resolvers.TagsResolver.ResolveWithErr(s.ContainerID)
	if err != nil {
		return fmt.Errorf("failed to resolve %s: %w", s.ContainerID, err)
	}
	return nil
}

type workloadAnalysisRequest struct {
	containerID string
	root        string
	initCounter uint64
}

// SBOMResolver is the Software Bill-Of-material resolver
type SBOMResolver struct {
	workloadsLock sync.RWMutex
	workloads     map[string]*SBOM
	probe         *Probe

	// context tags and attributes
	hostname    string
	source      string
	contextTags []string
}

// NewSBOMResolver returns a new instance of SBOMResolver
func NewSBOMResolver(p *Probe) (*SBOMResolver, error) {
	resolver := &SBOMResolver{
		probe:     p,
		workloads: make(map[string]*SBOM),
	}
	resolver.prepareContextTags()
	return resolver, nil
}

func (r *SBOMResolver) prepareContextTags() {
	// add hostname tag
	hostname, err := utils.GetHostname()
	if err != nil || hostname == "" {
		hostname = "unknown"
	}
	r.hostname = hostname
	r.contextTags = append(r.contextTags, fmt.Sprintf("host:%s", r.hostname))

	// merge tags from config
	for _, tag := range coreconfig.GetConfiguredTags(true) {
		if strings.HasPrefix(tag, "host") {
			continue
		}
		r.contextTags = append(r.contextTags, tag)
	}

	// add source tag
	r.source = utils.GetTagValue("source", r.contextTags)
	if len(r.source) == 0 {
		r.source = SBOMSource
		r.contextTags = append(r.contextTags, fmt.Sprintf("source:%s", SBOMSource))
	}
}

// Start starts the goroutine of the SBOM resolver
func (r *SBOMResolver) Start(ctx context.Context) {
	go func() {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		scannerTick := time.NewTicker(10 * time.Second)
		defer scannerTick.Stop()

		senderTick := time.NewTicker(1 * time.Minute)
		defer senderTick.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-scannerTick.C:
				r.AnalyzeWorkloads()
			case <-senderTick.C:
				if err := r.SendAvailableSBOMs(); err != nil {
					seclog.Errorf("couldn't send SBOMs: %w", err)
				}
			}
		}
	}()
}

// generateSBOM calls Trivy to generate the SBOM of a workload
func (r *SBOMResolver) generateSBOM(root string, workload *SBOM) error {
	seclog.Infof("generating SBOM for %s", root)

	reportFlagGroup := flag.NewReportFlagGroup()
	fsFlags := &flag.Flags{
		ReportFlagGroup: reportFlagGroup,
		ScanFlagGroup:   flag.NewScanFlagGroup()}
	globalFlags := flag.NewGlobalFlagGroup()

	opts, err := fsFlags.ToOptions("", []string{root}, globalFlags, os.Stdout)
	if err != nil {
		return err
	}

	opts.Format = "table"
	opts.Timeout = 60 * time.Second
	opts.ListAllPkgs = true

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	defer func() {
		if errors.Is(err, context.DeadlineExceeded) {
			seclog.Warnf("increase --timeout value")
		}
	}()

	runner, err := artifact.NewRunner(ctx, opts)
	if err != nil {
		if errors.Is(err, artifact.SkipScan) {
			return nil
		}
		return fmt.Errorf("init error: %w", err)
	}
	defer runner.Close(ctx)

	report, err := runner.ScanRootfs(ctx, opts)
	if err != nil {
		return fmt.Errorf("rootfs scan error: %w", err)
	}

	report, err = runner.Filter(ctx, opts, report)
	if err != nil {
		return fmt.Errorf("filter error: %w", err)
	}

	if err = runner.Report(opts, report); err != nil {
		return fmt.Errorf("report error: %w", err)
	}

	workload.report = report
	workload.shouldScan = false
	workload.rootCandidates.Purge()

	seclog.Infof("successfully generated SBOM for %s", root)

	return nil
}

// AnalyzeWorkloads iterates through the list of active workloads and scan the workloads when applicable
func (r *SBOMResolver) AnalyzeWorkloads() {
	workloadsToScan := r.listWorkloadsToScan()

	for _, workload := range workloadsToScan {
		if err := r.analyzeWorkload(workload); err != nil {
			seclog.Errorf("couldn't scan '%s': %w", workload.ContainerID, err)
		}
	}
}

func (r *SBOMResolver) listWorkloadsToScan() []*SBOM {
	r.workloadsLock.Lock()
	defer r.workloadsLock.Unlock()

	var out []*SBOM
	for _, workload := range r.workloads {
		workload.Lock()
		if workload.shouldScan {
			out = append(out, workload)
		}
		workload.Unlock()
	}
	return out
}

// analyzeWorkload generates the SBOM of the provided workload and send it to the security agent
func (r *SBOMResolver) analyzeWorkload(workload *SBOM) error {
	seclog.Infof("analyzing workload '%s': %v", workload.ContainerID, workload.rootCandidates.Keys())
	workload.Lock()
	defer workload.Unlock()

	var lastErr error
	for _, rootCandidateKey := range workload.rootCandidates.Keys() {
		rootCandidate, ok := workload.rootCandidates.Peek(rootCandidateKey)
		if !ok {
			continue
		}
		lastErr = r.generateSBOM(rootCandidate, workload)
		if lastErr == nil {
			break
		} else {
			seclog.Errorf("couldn't generate SBOM: %v", lastErr)
		}
	}
	if lastErr != nil {
		return lastErr
	}
	if workload.shouldScan {
		return fmt.Errorf("couldn't generate workload: all root candidates failed")
	}

	// build file cache
	for _, result := range workload.report.Results {
		for _, resultPkg := range result.Packages {
			pkg := &Package{
				name:    resultPkg.Name,
				version: resultPkg.Version,
			}
			for _, file := range resultPkg.SystemInstalledFiles {
				seclog.Infof("indexing %s as %+v", file, pkg)
				workload.files[file] = pkg
			}
		}
	}

	seclog.Infof("new sbom generated for '%s'", workload.ContainerID)
	return nil
}

// RefreshSBOM analyzes the file system of a workload to refresh its SBOM.
func (r *SBOMResolver) RefreshSBOM(process *model.ProcessCacheEntry) error {
	r.workloadsLock.Lock()
	defer r.workloadsLock.Unlock()
	workload, ok := r.workloads[process.ContainerID]
	if ok {
		if !workload.shouldScan {
			// purge old root candidates
			workload.rootCandidates.Purge()
		}
		workload.shouldScan = true
		workload.rootCandidates.Add(process.Pid, utils.ProcRootPath(int32(process.Pid)))
	} else {
		return r.newWorkloadEntry(process)
	}
	return nil
}

// ResolvePackage returns the Package that owns the provided file. Make sure the internal fields of "file" are properly
// resolved.
func (r *SBOMResolver) ResolvePackage(containerID string, file *model.FileEvent) *Package {
	r.workloadsLock.RLock()
	sbom, ok := r.workloads[containerID]
	r.workloadsLock.RUnlock()
	if !ok {
		return nil
	}

	seclog.Tracef("resolving %s for container %s", file.PathnameStr, containerID)

	sbom.RLock()
	defer sbom.RUnlock()

	seclog.Tracef("returning %v", sbom.files[file.PathnameStr])
	return sbom.files[file.PathnameStr]
}

// newWorkloadEntry (thread unsafe) creates a new SBOM entry for the workload designated by the provided process cache
// entry
func (r *SBOMResolver) newWorkloadEntry(process *model.ProcessCacheEntry) error {
	workload, err := NewSBOM(r, process)
	if err != nil {
		return err
	}
	r.workloads[process.ContainerID] = workload
	return nil
}

// Retain increments the reference counter of the SBOM of a workload
func (r *SBOMResolver) Retain(process *model.ProcessCacheEntry) {
	r.workloadsLock.Lock()
	defer r.workloadsLock.Unlock()

	if len(process.ContainerID) == 0 {
		return
	}

	workload, ok := r.workloads[process.ContainerID]
	if !ok {
		err := r.newWorkloadEntry(process)
		if err != nil {
			seclog.Errorf("couldn't create new SBOM entry for workload '%s': %w", err)
		}
		return
	}

	workload.Lock()
	defer workload.Unlock()
	workload.ReferenceCounter.Add(1)

	// add root candidate if the SBOM hasn't been generated yet
	if workload.shouldScan {
		workload.rootCandidates.Add(process.Pid, utils.ProcRootPath(int32(process.Pid)))
	}
	return
}

// Release decrements the reference counter of the SBOM of a workload
func (r *SBOMResolver) Release(process *model.ProcessCacheEntry) {
	r.workloadsLock.RLock()
	defer r.workloadsLock.RUnlock()

	workload, ok := r.workloads[process.ContainerID]
	if !ok {
		return
	}

	workload.Lock()
	defer workload.Unlock()
	counter := workload.ReferenceCounter.Sub(1)

	// delete root candidate
	workload.rootCandidates.Remove(process.Pid)

	// only delete sbom if it has already been sent, delay the deletion to the sender otherwise
	if counter <= 0 && workload.sent {
		r.deleteSBOM(process.ContainerID)
	}
}

// deleteSBOM thread unsafe delete all data indexed by the provided container ID
func (r *SBOMResolver) deleteSBOM(containerID string) {
	// remove SBOM entry
	delete(r.workloads, containerID)
}

// AddContextTags Adds the tags resolved by the resolver to the provided SBOM
func (r *SBOMResolver) AddContextTags(s *SBOM) {
	var tagName string
	var found bool

	dumpTagNames := make([]string, 0, len(s.Tags))
	for _, tag := range s.Tags {
		dumpTagNames = append(dumpTagNames, utils.GetTagName(tag))
	}

	for _, tag := range r.contextTags {
		tagName = utils.GetTagName(tag)
		found = false

		for _, dumpTagName := range dumpTagNames {
			if tagName == dumpTagName {
				found = true
				break
			}
		}

		if !found {
			s.Tags = append(s.Tags, tag)
		}
	}
}

// SendAvailableSBOMs sends all SBOMs that are ready to be sent
func (r *SBOMResolver) SendAvailableSBOMs() error {
	r.workloadsLock.Lock()
	defer r.workloadsLock.Unlock()
	now := time.Now()

	for _, workload := range r.workloads {
		if err := r.processWorkload(workload, now); err != nil {
			return err
		}
	}

	return nil
}

// processWorkload resolves the tags of the provided SBOM, send it and delete it when applicable
func (r *SBOMResolver) processWorkload(workload *SBOM, now time.Time) error {
	workload.Lock()
	defer workload.Unlock()

	if !workload.sent {
		// resolve tags
		_ = workload.resolveTags()
	}

	if now.After(workload.doNotSendBefore) {

		// check if we should send the SBOM now
		if !workload.sent {
			r.AddContextTags(workload)

			// resolve the service if it is defined
			workload.Service = utils.GetTagValue("service", workload.Tags)

			// send SBOM to the security agent
			sbomMsg, err := workload.ToSBOMMessage()
			if err != nil {
				return fmt.Errorf("couldn't serialize SBOM to protobuf: %w", err)
			}
			seclog.Infof("dispatching workload '%s'", workload.ContainerID)
			r.probe.DispatchSBOM(sbomMsg)
			workload.sent = true
		}

		// check if we should delete the sbom
		if workload.ReferenceCounter.Load() == 0 {
			r.deleteSBOM(workload.ContainerID)
		}
	}
	return nil
}
