// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf
// +build linux_bpf

package events

import (
	"fmt"
	"sync"
	"unsafe"

	ddebpf "github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/network/telemetry"
	manager "github.com/DataDog/ebpf-manager"
	"go.uber.org/atomic"
)

const (
	batchMapSuffix  = "_batches"
	eventsMapSuffix = "_batch_events"
)

// Consumer provides a standardized abstraction for consuming (batched) events from eBPF
type Consumer struct {
	syncRequest chan (chan struct{})
	offsets     *offsetManager
	handler     *ddebpf.PerfHandler
	batchReader *batchReader
	callback    func([]byte)

	// termination
	mux         sync.Mutex
	eventLoopWG sync.WaitGroup
	stopped     bool

	// telemetry
	eventsCount *telemetry.Metric
	missesCount *telemetry.Metric
	batchSize   *atomic.Int64
}

// NewConsumer instantiates a new event Consumer
// `callback` is executed once for every "event" generated on eBPF and must:
// 1) copy the data it wishes to hold since the underlying byte array is reclaimed;
// 2) be thread-safe, as the callback may be executed concurrently from multiple go-routines;
func NewConsumer(proto string, ebpf *manager.Manager, callback func([]byte)) (*Consumer, error) {
	batchMapName := proto + batchMapSuffix
	batchMap, found, _ := ebpf.GetMap(batchMapName)
	if !found {
		return nil, fmt.Errorf("unable to find map %s", batchMapName)
	}

	eventsMapName := proto + eventsMapSuffix
	eventsMap, found, _ := ebpf.GetMap(eventsMapName)
	if !found {
		return nil, fmt.Errorf("unable to find map %s", eventsMapName)
	}

	numCPUs := int(eventsMap.MaxEntries())
	offsets := newOffsetManager(numCPUs)
	batchReader, err := newBatchReader(offsets, batchMap, numCPUs)
	if err != nil {
		return nil, err
	}

	handlerMux.Lock()
	handler, ok := handlerByProtocol[proto]
	delete(handlerByProtocol, proto)
	handlerMux.Unlock()
	if !ok {
		return nil, fmt.Errorf("unable to detect perf handler. perhaps you forgot to call events.Configure()?")
	}

	// setup telemetry
	metricGroup := telemetry.NewMetricGroup(
		fmt.Sprintf("usm.%s", proto),
		telemetry.OptStatsd,
		telemetry.OptExpvar,
		telemetry.OptMonotonic,
	)

	eventsCount := metricGroup.NewMetric("events_captured")
	missesCount := metricGroup.NewMetric("events_missed")

	return &Consumer{
		callback:    callback,
		syncRequest: make(chan chan struct{}),
		offsets:     offsets,
		handler:     handler,
		batchReader: batchReader,

		// telemetry
		eventsCount: eventsCount,
		missesCount: missesCount,
		batchSize:   atomic.NewInt64(0),
	}, nil
}

// Start consumption of eBPF events
func (c *Consumer) Start() {
	c.eventLoopWG.Add(1)
	go func() {
		defer c.eventLoopWG.Done()
		for {
			select {
			case dataEvent, ok := <-c.handler.DataChannel:
				if !ok {
					return
				}

				b := batchFromEventData(dataEvent.Data)
				c.process(dataEvent.CPU, b, false)
				dataEvent.Done()
			case _, ok := <-c.handler.LostChannel:
				if !ok {
					return
				}

				missedEvents := c.batchSize.Load()
				c.missesCount.Add(missedEvents)
			case done, ok := <-c.syncRequest:
				if !ok {
					return
				}

				c.batchReader.ReadAll(func(cpu int, b *batch) {
					c.process(cpu, b, true)
				})
				close(done)
			}
		}
	}()
}

// Sync userpace with kernelspace by fetching all buffered data on eBPF
// Calling this will block until all eBPF map data has been fetched and processed
func (c *Consumer) Sync() {
	c.mux.Lock()
	if c.stopped {
		c.mux.Unlock()
		return
	}

	request := make(chan struct{})
	c.syncRequest <- request
	c.mux.Unlock()

	// Wait until all data is fetch from eBPF
	<-request
}

// Stop consuming data from eBPF
func (c *Consumer) Stop() {
	c.mux.Lock()
	defer c.mux.Unlock()

	if c.stopped {
		return
	}

	c.stopped = true
	c.batchReader.Stop()
	c.handler.Stop()
	c.eventLoopWG.Wait()
	close(c.syncRequest)
}

func (c *Consumer) process(cpu int, b *batch, syncing bool) {
	i, j := c.offsets.Get(cpu, b, syncing)

	// telemetry stuff
	c.batchSize.Store(int64(b.Cap))
	c.eventsCount.Add(int64(j - i))

	iter := newIterator(b, i, j)
	for data := iter.Next(); data != nil; data = iter.Next() {
		c.callback(data)
	}
}

func batchFromEventData(data []byte) *batch {
	return (*batch)(unsafe.Pointer(&data[0]))
}
