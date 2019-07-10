package microscanner

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/harbor-microscanner-adapter/pkg/image"
	"github.com/aquasecurity/harbor-microscanner-adapter/pkg/model/harbor"
	"github.com/aquasecurity/harbor-microscanner-adapter/pkg/model/microscanner"
	"github.com/danielpacak/docker-registry-client/pkg/auth"
	"github.com/danielpacak/docker-registry-client/pkg/registry"
	"log"
	"os"
)

type imageScanner struct {
	data microscanner.ScanResult
}

func NewScanner(dataFile string) (image.Scanner, error) {
	file, err := os.Open(dataFile)
	if err != nil {
		return nil, fmt.Errorf("opening data file: %v", err)
	}
	var data microscanner.ScanResult
	err = json.NewDecoder(file).Decode(&data)
	if err != nil {
		return nil, fmt.Errorf("decoding data file: %v", err)
	}
	return &imageScanner{
		data: data,
	}, nil
}

func (s *imageScanner) Scan(req harbor.ScanRequest) (*harbor.ScanResponse, error) {
	client, err := registry.NewClient(req.RegistryURL, auth.NewBearerTokenAuthorizer(req.RegistryToken))
	if err != nil {
		return nil, fmt.Errorf("constructing registry client: %v", err)
	}
	log.Printf("Saving image %s:%s", req.Repository, req.Digest)
	fsRoot, err := client.SaveImage(req.Repository, req.Digest, "/tmp/docker")
	if err != nil {
		return nil, fmt.Errorf("saving image: %v", err)
	}

	log.Printf("Image saved to %s", fsRoot)

	return &harbor.ScanResponse{
		DetailsKey: req.Digest,
	}, nil
}

func (s *imageScanner) GetResult(detailsKey string) (*harbor.ScanResult, error) {
	return s.toHarborScanResult(&s.data)
}

func (s *imageScanner) toHarborScanResult(sr *microscanner.ScanResult) (*harbor.ScanResult, error) {
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

	severity, overview := s.toComponentsOverview(sr)

	return &harbor.ScanResult{
		Severity:        severity,
		Overview:        overview,
		Vulnerabilities: items,
	}, nil
}

// TODO Do the actual mapping
func (s *imageScanner) toComponentsOverview(_ *microscanner.ScanResult) (harbor.Severity, *harbor.ComponentsOverview) {
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
