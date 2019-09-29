package model

import (
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/microscanner"
	log "github.com/sirupsen/logrus"
	"time"
)

// Transformer wraps the Transform method.
//
// Transform transforms MicroScanner's scan report to Harbor's os package vulnerability report.
type Transformer interface {
	Transform(req harbor.ScanRequest, sr *microscanner.ScanReport) (*harbor.VulnerabilityReport, error)
}

type transformer struct {
}

func NewTransformer() Transformer {
	return &transformer{}
}

func (t *transformer) Transform(req harbor.ScanRequest, sr *microscanner.ScanReport) (*harbor.VulnerabilityReport, error) {
	var items []harbor.VulnerabilityItem

	for _, resourceScan := range sr.Resources {
		for _, vln := range resourceScan.Vulnerabilities {
			items = append(items, harbor.VulnerabilityItem{
				ID:          vln.Name,
				Pkg:         resourceScan.Resource.Name,
				Version:     resourceScan.Resource.Version,
				FixVersion:  vln.FixVersion,
				Severity:    t.toHarborSeverity(vln.NVDSeverity),
				Description: vln.Description,
				Links:       []string{vln.NVDURL},
			})
		}
	}

	return &harbor.VulnerabilityReport{
		GeneratedAt: time.Now(),
		Artifact:    req.Artifact,
		Scanner: harbor.Scanner{
			Name:    "MicroScanner",
			Vendor:  "Aqua Security",
			Version: "3.0.5",
		},
		Severity:        t.toHighestSeverity(sr),
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
		log.WithField("severity", severity).Warn("Unknown microscanner severity")
		return harbor.SevUnknown
	}
}

func (t *transformer) toHighestSeverity(sr *microscanner.ScanReport) harbor.Severity {
	overallSev := harbor.SevNone

	for _, resourceScan := range sr.Resources {
		for _, vln := range resourceScan.Vulnerabilities {
			sev := t.toHarborSeverity(vln.NVDSeverity)
			if sev > overallSev {
				overallSev = sev
			}
		}
	}

	return overallSev
}
