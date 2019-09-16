package microscanner

import (
	"fmt"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/docker"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/store"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"net/url"
	"os"
	"path/filepath"
)

// Scanner wraps the Scan method.
// TODO Rename to ScannerManager
type Scanner interface {
	Scan(scanJobID string, request harbor.ScanRequest) error
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

func (s *scanner) Scan(scanJobID string,req harbor.ScanRequest) error {

	err := s.scan(scanJobID, req)
	if err != nil {
		log.Errorf("Scan failed: %v", err)
		err = s.dataStore.UpdateScanJobStatus(scanJobID, job.Pending, job.Failed)
		if err != nil {
			return fmt.Errorf("updating scan job as failed: %v", err)
		}
	}
	return nil
}

func (s *scanner) scan(scanID string, req harbor.ScanRequest) error {
	err := s.dataStore.UpdateScanJobStatus(scanID, job.Queued, job.Pending)
	if err != nil {
		return fmt.Errorf("updating scan job status: %v", err)
	}

	dockerConfig, err := s.authorizer.Authorize(req)
	if err != nil {
		return fmt.Errorf("authorizing request: %v", err)
	}
	defer func() {
		configDir := filepath.Dir(dockerConfig)
		log.Debugf("Deleting temporary Docker config dir: %s", configDir)
		err := os.RemoveAll(configDir)
		if err != nil {
			log.Warnf("Error while removing Docker config dir: %v", err)
		}
	}()

	imageRef, err := s.ToImageRef(req)
	if err != nil {
		return fmt.Errorf("getting image ref: %v", err)
	}

	microScannerReport, err := s.wrapper.Run(imageRef, dockerConfig)
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

// ToImageRef returns Docker image reference for the given ScanRequest.
// Example: core.harbor.domain/scanners/mysql@sha256:3b00a364fb74246ca119d16111eb62f7302b2ff66d51e373c2bb209f8a1f3b9e
func (s *scanner) ToImageRef(req harbor.ScanRequest) (string, error) {
	registryURL, err := url.Parse(req.Registry.URL)
	if err != nil {
		return "", xerrors.Errorf("parsing registry URL: %w", err)
	}
	return fmt.Sprintf("%s/%s@%s", registryURL.Host, req.Artifact.Repository, req.Artifact.Digest), nil
}
