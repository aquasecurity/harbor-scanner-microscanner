package model

import (
	"github.com/aquasecurity/microscanner-proxy/pkg/model/harbor"
	"github.com/aquasecurity/microscanner-proxy/pkg/model/microscanner"
)

func Transform(digest string, sr *microscanner.ScanResult) (*harbor.ScanResult, error) {
	var items []*harbor.VulnerabilityItem

	for _, resourceScan := range sr.Resources {
		for _, vln := range resourceScan.Vulnerabilities {
			items = append(items, &harbor.VulnerabilityItem{
				ID:          vln.Name,
				Pkg:         resourceScan.Resource.Name,
				Version:     resourceScan.Resource.Version,
				Link:        vln.VendorURL,
				Description: vln.Description,
				// TODO Map Severity property
				Severity: harbor.SevHigh,
				// TODO Map Fixed property
				Fixed: "linux.org",
			})
		}
	}

	severity, overview := transformToComponentsOverview(sr)

	return &harbor.ScanResult{
		Digest:          digest,
		Severity:        severity,
		Overview:        overview,
		Vulnerabilities: items,
	}, nil
}

// TODO Do the actual mapping
func transformToComponentsOverview(_ *microscanner.ScanResult) (harbor.Severity, *harbor.ComponentsOverview) {
	return harbor.SevHigh, &harbor.ComponentsOverview{
		Total: 24 + 13 + 7 + 1 + 5,
		Summary: []*harbor.ComponentsOverviewEntry{
			{Sev: 1, Count: 24},
			{Sev: 2, Count: 13},
			{Sev: 3, Count: 7},
			{Sev: 4, Count: 1},
			{Sev: 5, Count: 5},
		},
	}
}
