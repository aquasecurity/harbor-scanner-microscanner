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

	testCases := []struct {
		Name               string
		ScanRequest        harbor.ScanRequest
		MicroScannerReport *microscanner.ScanReport
		HarborReport       *harbor.VulnerabilityReport
		ScanReports        *store.ScanReports
	}{
		{
			Name: "Happy path",
			ScanRequest: harbor.ScanRequest{
				ID:                 scanID.String(),
				RegistryURL:        "docker.io",
				ArtifactRepository: "library/mongo",
				ArtifactDigest:     "sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e",
			},
			MicroScannerReport: &microscanner.ScanReport{},
			HarborReport:       &harbor.VulnerabilityReport{},
			ScanReports: &store.ScanReports{
				HarborVulnerabilityReport: &harbor.VulnerabilityReport{},
				MicroScannerReport:        &microscanner.ScanReport{},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			scanRequest := tc.ScanRequest

			authorizer := mocks.NewAuthorizer()
			wrapper := mocks.NewWrapper()
			transformer := mocks.NewTransformer()
			dataStore := mocks.NewDataStore()

			dataStore.On("UpdateScanJobStatus", scanID, job.Queued, job.Pending).Return(nil)
			authorizer.On("Authorize", scanRequest).Return(stringPtr("/tmp/.docker"), nil)
			wrapper.On("Run",
				"docker.io/library/mongo@sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e",
				"/tmp/.docker").
				Return(tc.MicroScannerReport, nil)
			transformer.On("Transform", tc.MicroScannerReport).Return(tc.HarborReport, nil)
			dataStore.On("SaveScanReports", scanID, tc.ScanReports).Return(nil)
			dataStore.On("UpdateScanJobStatus", scanID, job.Pending, job.Finished).Return(nil)

			scanner := NewScanner(authorizer, wrapper, transformer, dataStore)

			err := scanner.Scan(scanRequest)
			require.NoError(t, err)

			authorizer.AssertExpectations(t)
			wrapper.AssertExpectations(t)
			transformer.AssertExpectations(t)
			dataStore.AssertExpectations(t)
		})
	}

}

func stringPtr(val string) *string {
	return &val
}
