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

func (s *scanner) Scan(scanJobID string, req harbor.ScanRequest) error {
	err := s.scanE(scanJobID, req)
	if err != nil {
		log.WithError(err).Error("Scan failed")
		err = s.dataStore.UpdateStatus(scanJobID, job.Failed, err.Error())
		if err != nil {
			return fmt.Errorf("updating scan job as failed: %v", err)
		}
	}
	return nil
}

func (s *scanner) scanE(scanID string, req harbor.ScanRequest) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}
	}()

	err = s.dataStore.UpdateStatus(scanID, job.Pending)
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
		return fmt.Errorf("wrapper script failed: %v", err)
	}

	harborVulnerabilityReport, err := s.transformer.Transform(req, microScannerReport)
	if err != nil {
		return fmt.Errorf("report transformer failed: %v", err)
	}

	err = s.dataStore.UpdateReports(scanID, job.ScanReports{
		MicroScannerReport:        microScannerReport,
		HarborVulnerabilityReport: harborVulnerabilityReport,
	})

	if err != nil {
		return fmt.Errorf("saving scan reports: %v", err)
	}

	err = s.dataStore.UpdateStatus(scanID, job.Finished)
	if err != nil {
		return fmt.Errorf("updating scan job status: %v", err)
	}

	return err
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
