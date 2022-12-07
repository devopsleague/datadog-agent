// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

package containerimage

import (
	"time"

	"github.com/DataDog/datadog-agent/pkg/aggregator"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	"github.com/DataDog/datadog-agent/pkg/workloadmeta"

	"github.com/DataDog/agent-payload/v5/contimage"
	model "github.com/DataDog/agent-payload/v5/contimage"
)

type processor struct {
	queue chan *model.ContainerImage
}

func newProcessor(sender aggregator.Sender, maxNbItem int, maxRetentionTime time.Duration) *processor {
	return &processor{
		queue: newQueue(maxNbItem, maxRetentionTime, func(images []*model.ContainerImage) {
			payload := model.ContainerImagePayload{
				Version: "v1",
				Images:  images,
			}

			sender.ContainerImage([]contimage.ContainerImagePayload{payload})
		}),
	}
}

func (p *processor) processEvents(evBundle workloadmeta.EventBundle) {
	close(evBundle.Ch)

	log.Tracef("Processing %d events", len(evBundle.Events))

	for _, event := range evBundle.Events {
		p.processImage(event.Entity.(*workloadmeta.ContainerImageMetadata))
	}
}

func (p *processor) processRefresh(allImages []*workloadmeta.ContainerImageMetadata) {
	// TODO: implement a less naive approach
	for _, img := range allImages {
		p.processImage(img)
	}
}

func (p *processor) processImage(img *workloadmeta.ContainerImageMetadata) {
	p.queue <- &model.ContainerImage{
		Id:          img.ID,
		Registry:    "", // TODO: check what to put here
		ShortName:   img.ShortName,
		Tags:        img.RepoTags,
		Digest:      img.ID,
		Size_:       img.SizeBytes,
		RepoDigests: img.RepoDigests,
		Os: &model.ContainerImage_OperatingSystem{
			Name:         img.OS,
			Version:      img.Variant, // TODO: check if version should be renamed variant or the other way round.
			Architecture: img.Architecture,
		},
		Layers: nil, // TODO: complete
	}
}

func (p *processor) stop() {
	close(p.queue)
}
