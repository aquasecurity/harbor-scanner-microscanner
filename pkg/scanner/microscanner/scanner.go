package microscanner

import (
	"errors"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/microscanner"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/scanner"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/store"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

type imageScanner struct {
	cfg         *etc.Config
	wrapper     Wrapper
	transformer model.Transformer
	store       store.DataStore
}

func NewScanner(cfg *etc.Config, wrapper Wrapper, transformer model.Transformer, store store.DataStore) (scanner.Scanner, error) {
	return &imageScanner{
		cfg:         cfg,
		transformer: transformer,
		store:       store,
		wrapper:     wrapper,
	}, nil
}

func (s *imageScanner) GetMetadata() (*harbor.ScannerMetadata, error) {
	return &harbor.ScannerMetadata{
		Name:    "MicroScanner",
		Vendor:  "Aqua Security",
		Version: "3.0.5",
		Capabilities: []*harbor.Capability{
			{
				ArtifactMIMETypes: []string{
					"application/vnd.oci.image.manifest.v1+json",
					"application/vnd.docker.distribution.manifest.v2+json",
				},
				ReportMIMETypes: []string{
					"application/vnd.harbor.scanner.report.vulnerability.v1+json",
				},
			},
		},
	}, nil
}

func (s *imageScanner) Scan(req harbor.ScanRequest) error {
	registryURL := req.RegistryURL
	if s.cfg.RegistryURL != "" {
		log.Debugf("Overwriting registry URL %s with %s", req.RegistryURL, s.cfg.RegistryURL)
		registryURL = s.cfg.RegistryURL
	}

	imageToScan := fmt.Sprintf("%s/%s@%s", registryURL, req.ArtifactRepository, req.ArtifactDigest)
	sr, err := s.wrapper.Run(imageToScan)
	if err != nil {
		return fmt.Errorf("running microscanner wrapper script: %v", err)
	}

	hvr, err := s.transformer.Transform(sr)
	if err != nil {
		return fmt.Errorf("transforming microscanner model to harbor model: %v", err)
	}

	scanID, err := uuid.Parse(req.ID)
	if err != nil {
		return err
	}

	err = s.store.SaveScan(scanID, &store.Scan{
		MicroScannerReport:        sr,
		HarborVulnerabilityReport: hvr,
	})

	if err != nil {
		return fmt.Errorf("saving scan object: %v", err)
	}
	return nil
}

func (s *imageScanner) GetHarborVulnerabilityReport(scanRequestID string) (*harbor.VulnerabilityReport, error) {
	if scanRequestID == "" {
		return nil, errors.New("scanRequestID must not be blank")
	}

	scanID, err := uuid.Parse(scanRequestID)
	if err != nil {
		return nil, err
	}

	scan, err := s.store.GetScan(scanID)
	if err != nil {
		return nil, err
	}
	return scan.HarborVulnerabilityReport, nil
}

func (s *imageScanner) GetMicroScannerReport(scanRequestID string) (*microscanner.ScanReport, error) {
	if scanRequestID == "" {
		return nil, errors.New("scanRequestID must not be blank")
	}

	scanID, err := uuid.Parse(scanRequestID)
	if err != nil {
		return nil, err
	}

	scan, err := s.store.GetScan(scanID)
	if err != nil {
		return nil, err
	}
	return scan.MicroScannerReport, nil
}
