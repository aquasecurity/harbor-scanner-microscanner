package microscanner

import (
	"fmt"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/docker"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/store"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"os"
)

// Scanner wraps the Scan method.
type Scanner interface {
	Scan(req harbor.ScanRequest) error
}

type scanner struct {
	authorizer  docker.Authorizer
	wrapper     Wrapper
	transformer model.Transformer
	dataStore   store.DataStore
}

func NewScanner(authorizer docker.Authorizer, wrapper Wrapper, transformer model.Transformer, dataStore store.DataStore) Scanner {
	return &scanner{
		authorizer:  authorizer,
		transformer: transformer,
		dataStore:   dataStore,
		wrapper:     wrapper,
	}
}

func (s *scanner) Scan(req harbor.ScanRequest) error {
	scanID, err := uuid.Parse(req.ID)
	if err != nil {
		return fmt.Errorf("parsing scan request ID: %v", err)
	}

	err = s.scan(scanID, req)
	if err != nil {
		log.Errorf("Scan failed: %v", err)
		err = s.dataStore.UpdateScanJobStatus(scanID, job.Pending, job.Failed)
		if err != nil {
			return fmt.Errorf("updating scan job as failed: %v", err)
		}
	}
	return nil
}

func (s *scanner) scan(scanID uuid.UUID, req harbor.ScanRequest) error {
	err := s.dataStore.UpdateScanJobStatus(scanID, job.Queued, job.Pending)
	if err != nil {
		return fmt.Errorf("updating scan job status: %v", err)
	}

	dockerConfig, err := s.authorizer.Authorize(req)
	if err != nil {
		return fmt.Errorf("authorizing request: %v", err)
	}
	defer func() {
		err := os.RemoveAll(dockerConfig)
		if err != nil {
			log.Warnf("Error while removing Docker config directory: %v", err)
		}
	}()

	imageToScan := fmt.Sprintf("%s/%s@%s", req.RegistryURL, req.ArtifactRepository, req.ArtifactDigest)
	microScannerReport, err := s.wrapper.Run(imageToScan, dockerConfig)
	if err != nil {
		return fmt.Errorf("running microscanner wrapper script: %v", err)
	}

	harborVulnerabilityReport, err := s.transformer.Transform(microScannerReport)
	if err != nil {
		return fmt.Errorf("transforming microscanner report to harbor vulnerability report: %v", err)
	}

	err = s.dataStore.SaveScanReports(scanID, &store.ScanReports{
		MicroScannerReport:        microScannerReport,
		HarborVulnerabilityReport: harborVulnerabilityReport,
	})

	if err != nil {
		return fmt.Errorf("saving scan reports: %v", err)
	}

	err = s.dataStore.UpdateScanJobStatus(scanID, job.Pending, job.Finished)
	if err != nil {
		return fmt.Errorf("updating scan job status: %v", err)
	}

	return nil
}
