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

// SBOMResolver is the Software Bill-Of-material resolver
type SBOMResolver struct {
	workloadsLock sync.RWMutex
	workloads     map[string]*SBOM
	scannerChan   chan *SBOM
	probe         *Probe

	// context tags and attributes
	hostname    string
	source      string
	contextTags []string
}

// NewSBOMResolver returns a new instance of SBOMResolver
func NewSBOMResolver(p *Probe) (*SBOMResolver, error) {
	resolver := &SBOMResolver{
		probe:       p,
		workloads:   make(map[string]*SBOM),
		scannerChan: make(chan *SBOM, 100),
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

		senderTick := time.NewTicker(10 * time.Second)
		defer senderTick.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case workload := <-r.scannerChan:
				if err := r.analyzeWorkload(workload); err != nil {
					seclog.Errorf("couldn't scan '%s': %w", workload.ContainerID, err)
				}
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

	seclog.Infof("SBOM successfully generated from %s", root)

	return nil
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
				seclog.Tracef("indexing %s as %+v", file, pkg)
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
		workload.Lock()
		defer workload.Unlock()

		if !workload.shouldScan {
			// purge old root candidates
			workload.rootCandidates.Purge()
		}
		workload.shouldScan = true
		workload.rootCandidates.Add(process.Pid, utils.ProcRootPath(int32(process.Pid)))
	} else {
		var err error
		workload, err = r.newWorkloadEntry(process)
		if err != nil {
			return err
		}
	}

	// push workload to the scanner chan
	select {
	case r.scannerChan <- workload:
	default:
	}
	return nil
}

// ResolvePackage returns the Package that owns the provided file. Make sure the internal fields of "file" are properly
// resolved.
func (r *SBOMResolver) ResolvePackage(containerID string, file *model.FileEvent) *Package {
	r.workloadsLock.RLock()
	defer r.workloadsLock.RUnlock()
	workload, ok := r.workloads[containerID]
	if !ok {
		return nil
	}

	seclog.Tracef("resolving %s for container %s", file.PathnameStr, containerID)

	workload.RLock()
	defer workload.RUnlock()

	seclog.Tracef("returning %v", workload.files[file.PathnameStr])
	return workload.files[file.PathnameStr]
}

// newWorkloadEntry (thread unsafe) creates a new SBOM entry for the workload designated by the provided process cache
// entry
func (r *SBOMResolver) newWorkloadEntry(process *model.ProcessCacheEntry) (*SBOM, error) {
	workload, err := NewSBOM(r, process)
	if err != nil {
		return nil, err
	}
	r.workloads[process.ContainerID] = workload
	return workload, nil
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
		var err error
		workload, err = r.newWorkloadEntry(process)
		if err != nil {
			seclog.Errorf("couldn't create new SBOM entry for workload '%s': %w", err)
		}

		// push workload to the scanner chan
		select {
		case r.scannerChan <- workload:
		default:
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
	seclog.Infof("deleting SBOM entry for '%s'", containerID)
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
	// make sure we don't lock the main map of workloads for too long
	r.workloadsLock.Lock()
	allWorkloads := make([]*SBOM, 0, len(r.workloads))
	for _, workload := range r.workloads {
		allWorkloads = append(allWorkloads, workload)
	}
	r.workloadsLock.Unlock()
	now := time.Now()

	for _, workload := range allWorkloads {
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
			r.workloadsLock.Lock()
			r.deleteSBOM(workload.ContainerID)
			r.workloadsLock.Unlock()
		}
	}
	return nil
}
