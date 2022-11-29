// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux
// +build linux

package probe

import (
	"fmt"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	trivyMarshaler "github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
	types "github.com/aquasecurity/trivy/pkg/types"
	"github.com/golang/protobuf/ptypes/timestamp"

	"github.com/DataDog/datadog-agent/pkg/security/api"
	ddCycloneDXProto "github.com/DataDog/datadog-agent/pkg/security/api/cyclonedx"
	"github.com/DataDog/datadog-agent/pkg/security/seclog"
)

// ToSBOMMessage returns an *api.SBOMMessage instance from an SBOM instance
func (s *SBOM) ToSBOMMessage() (*api.SBOMMessage, error) {
	cycloneDXBOM, err := reportToDDCycloneDXProto(s.report)
	if err != nil {
		return nil, err
	}

	msg := &api.SBOMMessage{
		Host:        s.Host,
		Service:     s.Service,
		Source:      s.Source,
		Tags:        make([]string, len(s.Tags)),
		BOM:         cycloneDXBOM,
		ContainerID: s.ContainerID,
	}
	copy(msg.Tags, s.Tags)
	return msg, nil
}

func reportToDDCycloneDXProto(report types.Report) (*ddCycloneDXProto.Bom, error) {
	marshaler := trivyMarshaler.NewMarshaler("")
	cycloneDXBom, err := marshaler.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("couldn't marshal report: %w", err)
	}
	return cycloneDXBomToProto(cycloneDXBom), nil
}

func cycloneDXBomToProto(bom *cyclonedx.BOM) *ddCycloneDXProto.Bom {
	if bom == nil {
		return nil
	}

	cycloneDXProto := &ddCycloneDXProto.Bom{
		SpecVersion:  bom.SpecVersion,
		Version:      int32(bom.Version),
		SerialNumber: bom.SerialNumber,
	}

	if bom.Metadata != nil {
		cycloneDXProto.Metadata = cycloneDXMetadataToProto(*bom.Metadata)
	}

	if bom.Components != nil {
		cycloneDXProto.Components = make([]*ddCycloneDXProto.Component, 0, len(*bom.Components))
		for _, elem := range *bom.Components {
			cycloneDXProto.Components = append(cycloneDXProto.Components, cycloneDXComponentToProto(elem))
		}
	}

	if bom.Services != nil {
		// TODO
	}

	if bom.ExternalReferences != nil {
		// TODO
	}

	if bom.Dependencies != nil {
		// TODO
	}

	if bom.Compositions != nil {
		// TODO
	}

	if bom.Properties != nil {
		// TODO
	}

	if bom.Properties != nil {
		// TODO
	}

	if bom.Vulnerabilities != nil {
		// TODO
	}
	return cycloneDXProto
}

func cycloneDXComponentTypeToProto(componentType cyclonedx.ComponentType) ddCycloneDXProto.Classification {
	switch componentType {
	case cyclonedx.ComponentTypeApplication:
		return ddCycloneDXProto.Classification_CLASSIFICATION_APPLICATION
	case cyclonedx.ComponentTypeFramework:
		return ddCycloneDXProto.Classification_CLASSIFICATION_FRAMEWORK
	case cyclonedx.ComponentTypeLibrary:
		return ddCycloneDXProto.Classification_CLASSIFICATION_LIBRARY
	case cyclonedx.ComponentTypeOS:
		return ddCycloneDXProto.Classification_CLASSIFICATION_OPERATING_SYSTEM
	case cyclonedx.ComponentTypeDevice:
		return ddCycloneDXProto.Classification_CLASSIFICATION_DEVICE
	case cyclonedx.ComponentTypeFile:
		return ddCycloneDXProto.Classification_CLASSIFICATION_FILE
	case cyclonedx.ComponentTypeContainer:
		return ddCycloneDXProto.Classification_CLASSIFICATION_CONTAINER
	case cyclonedx.ComponentTypeFirmware:
		return ddCycloneDXProto.Classification_CLASSIFICATION_FIRMWARE
	default:
		return ddCycloneDXProto.Classification_CLASSIFICATION_NULL
	}
}

func cycloneDXComponentToProto(elem cyclonedx.Component) *ddCycloneDXProto.Component {
	return &ddCycloneDXProto.Component{
		BomRef:   elem.BOMRef,
		MimeType: elem.MIMEType,
		Type:     cycloneDXComponentTypeToProto(elem.Type),
		Name:     elem.Name,
		Version:  elem.Version,
		Purl:     elem.PackageURL,
	}
}

func cycloneDXMetadataToProto(metadata cyclonedx.Metadata) *ddCycloneDXProto.Metadata {
	parsedTime, err := time.Parse("2006-01-02T15:04:05+00:00", metadata.Timestamp)
	if err != nil {
		seclog.Errorf("couldn't parse the exact timestamp, falling back to time.Now()")
		parsedTime = time.Now()
	}

	return &ddCycloneDXProto.Metadata{
		Timestamp: &timestamp.Timestamp{
			Seconds: parsedTime.Unix(),
		},
		Component: cycloneDXComponentToProto(*metadata.Component),
	}
}
