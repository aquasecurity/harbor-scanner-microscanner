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

	registryURL := req.RegistryURL
	if s.cfg.RegistryURL != "" {
		log.Printf("Overwriting registry URL %s with %s", req.RegistryURL, s.cfg.RegistryURL)
		registryURL = s.cfg.RegistryURL
	}

	imageToScan := fmt.Sprintf("%s/%s:%s", registryURL, req.Repository, req.Tag)
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
				Severity:    s.toHarborSeverity(vln.NVDSeverity),
				Pkg:         resourceScan.Resource.Name,
				Version:     resourceScan.Resource.Version,
				Description: vln.Description,
				Link:        vln.NVDURL,
				Fixed:       vln.FixVersion,
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

func (s *imageScanner) toHarborSeverity(severity string) harbor.Severity {
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

func (s *imageScanner) toComponentsOverview(sr *microscanner.ScanResult) (harbor.Severity, *harbor.ComponentsOverview) {
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
			sev := s.toHarborSeverity(vln.NVDSeverity)
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
