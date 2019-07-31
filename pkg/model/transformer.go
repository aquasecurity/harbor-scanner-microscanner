package model

import (
	"github.com/danielpacak/harbor-scanner-contract/pkg/model/harbor"
	"github.com/danielpacak/harbor-scanner-microscanner/pkg/model/microscanner"
	"log"
)

// Transformer wraps the Transform method.
//
// Transform transforms Microscanner's scan results model to Harbor's model.
type Transformer interface {
	Transform(sr *microscanner.ScanResult) (*harbor.ScanResult, error)
}

type transformer struct {
}

func NewTransformer() Transformer {
	return &transformer{}
}

func (t *transformer) Transform(sr *microscanner.ScanResult) (*harbor.ScanResult, error) {
	var items []*harbor.VulnerabilityItem

	for _, resourceScan := range sr.Resources {
		for _, vln := range resourceScan.Vulnerabilities {
			items = append(items, &harbor.VulnerabilityItem{
				ID:          vln.Name,
				Severity:    t.toHarborSeverity(vln.NVDSeverity),
				Pkg:         resourceScan.Resource.Name,
				Version:     resourceScan.Resource.Version,
				Description: vln.Description,
				Link:        vln.NVDURL,
				Fixed:       vln.FixVersion,
			})
		}
	}

	severity, overview := t.toComponentsOverview(sr)

	return &harbor.ScanResult{
		Severity:        severity,
		Overview:        overview,
		Vulnerabilities: items,
	}, nil
}

func (t *transformer) toHarborSeverity(severity string) harbor.Severity {
	switch severity {
	case "high":
		return harbor.SevHigh
	case "medium":
		return harbor.SevMedium
	case "low":
		return harbor.SevLow
	default:
		log.Printf("Unknown microscanner severity `%s`", severity)
		return harbor.SevUnknown
	}
}

func (t *transformer) toComponentsOverview(sr *microscanner.ScanResult) (harbor.Severity, *harbor.ComponentsOverview) {
	overallSev := harbor.SevNone
	total := 0
	sevToCount := map[harbor.Severity]int{
		harbor.SevHigh:    0,
		harbor.SevMedium:  0,
		harbor.SevLow:     0,
		harbor.SevUnknown: 0,
		harbor.SevNone:    0,
	}

	for _, resourceScan := range sr.Resources {
		for _, vln := range resourceScan.Vulnerabilities {
			sev := t.toHarborSeverity(vln.NVDSeverity)
			sevToCount[sev]++
			total++
			if sev > overallSev {
				overallSev = sev
			}
		}
	}

	var summary []*harbor.ComponentsOverviewEntry
	for k, v := range sevToCount {
		summary = append(summary, &harbor.ComponentsOverviewEntry{
			Sev:   int(k),
			Count: v,
		})
	}

	return overallSev, &harbor.ComponentsOverview{
		Total:   total,
		Summary: summary,
	}
}
