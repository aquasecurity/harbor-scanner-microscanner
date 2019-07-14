package microscanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aquasecurity/harbor-microscanner-adapter/pkg/etc"
	"github.com/aquasecurity/harbor-microscanner-adapter/pkg/image"
	"github.com/aquasecurity/harbor-microscanner-adapter/pkg/model/harbor"
	"github.com/aquasecurity/harbor-microscanner-adapter/pkg/model/microscanner"
	"github.com/google/uuid"
	"log"
	"os"
	"path/filepath"
)

type imageScanner struct {
	cfg     *etc.Config
	wrapper *Wrapper
	data    microscanner.ScanResult
}

func NewScanner(cfg *etc.Config) (image.Scanner, error) {
	return &imageScanner{
		cfg:     cfg,
		wrapper: NewWrapper(cfg),
	}, nil
}

func (s *imageScanner) Scan(req harbor.ScanRequest) (*harbor.ScanResponse, error) {
	scanID, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}
	log.Printf("RegistryURL: %s", req.RegistryURL)
	log.Printf("Repository: %s", req.Repository)
	log.Printf("Tag: %s", req.Tag)
	log.Printf("Digest: %s", req.Digest)
	log.Printf("Scan request %s", scanID.String())
	imageToScan := fmt.Sprintf("%s/%s:%s", req.RegistryURL, req.Repository, req.Tag)
	err = s.execWrapperScript(scanID, imageToScan)
	if err != nil {
		return nil, err
	}

	return &harbor.ScanResponse{
		DetailsKey: scanID.String(),
	}, nil
}

// execWrapperScript executes the microscanner-wrapper scan.sh script and save the result JSON to a file.
func (s *imageScanner) execWrapperScript(scanID uuid.UUID, image string) error {
	out, err := s.wrapper.Scan(image)
	if err != nil {
		return err
	}

	f, err := os.Create(s.GetScanResultFilePath(scanID))
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	_, err = f.WriteString(out)
	if err != nil {
		return err
	}
	return nil
}

func (s *imageScanner) GetResult(detailsKey string) (*harbor.ScanResult, error) {
	if detailsKey == "" {
		return nil, errors.New("detailsKey must not be nil")
	}

	scanID, err := uuid.Parse(detailsKey)
	if err != nil {
		return nil, err
	}

	file, err := os.Open(s.GetScanResultFilePath(scanID))
	if err != nil {
		return nil, fmt.Errorf("opening scan result file: %v", err)
	}
	var data microscanner.ScanResult
	err = json.NewDecoder(file).Decode(&data)
	if err != nil {
		return nil, fmt.Errorf("decoding result file: %v", err)
	}
	return s.toHarborScanResult(&data)
}

func (s *imageScanner) GetScanResultFilePath(scanID uuid.UUID) string {
	return filepath.Join("/tmp/", scanID.String()+".json")
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
