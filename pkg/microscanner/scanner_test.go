package microscanner

import (
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/mocks"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/microscanner"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/store"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestScanner_Scan(t *testing.T) {
	scanID := uuid.New()
	scanRequest := harbor.ScanRequest{
		ID:                 scanID.String(),
		RegistryURL:        "docker.io",
		ArtifactRepository: "library/mongo",
		ArtifactDigest:     "sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e",
	}
	microScannerReport := &microscanner.ScanReport{}
	harborReport := &harbor.VulnerabilityReport{}
	scanReports := &store.ScanReports{
		HarborVulnerabilityReport: harborReport,
		MicroScannerReport:        microScannerReport,
	}

	wrapper := mocks.NewWrapperMock()
	transformer := mocks.NewTransformer()
	dataStore := mocks.NewDataStore()

	dataStore.On("UpdateScanJobStatus", scanID, job.Queued, job.Pending).Return(nil)
	wrapper.On("Run", "docker.io/library/mongo@sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e").Return(microScannerReport, nil)
	transformer.On("Transform", microScannerReport).Return(harborReport, nil)
	dataStore.On("SaveScanReports", scanID, scanReports).Return(nil)
	dataStore.On("UpdateScanJobStatus", scanID, job.Pending, job.Finished).Return(nil)

	scanner := NewScanner(wrapper, transformer, dataStore)

	err := scanner.Scan(scanRequest)
	require.NoError(t, err)

	wrapper.AssertExpectations(t)
	transformer.AssertExpectations(t)
	dataStore.AssertExpectations(t)
}
