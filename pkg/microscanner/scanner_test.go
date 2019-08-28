package microscanner

import (
	"errors"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/mocks"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/microscanner"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/store"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
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
	harborReport := &harbor.VulnerabilityReport{}
	microScannerReport := &microscanner.ScanReport{}
	scanReports := &store.ScanReports{
		HarborVulnerabilityReport: harborReport,
		MicroScannerReport:        microScannerReport,
	}

	testCases := []struct {
		Name string
		Skip *string

		ScanRequest            harbor.ScanRequest
		MicroScannerReport     *microscanner.ScanReport
		HarborReport           *harbor.VulnerabilityReport
		ScanReports            *store.ScanReports
		AuthorizerExpectation  *mocks.Expectation
		WrapperExpectation     *mocks.Expectation
		TransformerExpectation *mocks.Expectation
		DataStoreExpectations  []*mocks.Expectation

		ExpectedError error
	}{
		{
			Name:               "Happy path",
			ScanRequest:        scanRequest,
			MicroScannerReport: microScannerReport,
			HarborReport:       harborReport,
			ScanReports:        scanReports,
			AuthorizerExpectation: &mocks.Expectation{
				MethodName:      "Authorize",
				Arguments:       []interface{}{scanRequest},
				ReturnArguments: []interface{}{stringPtr("/tmp/.docker"), nil},
			},
			WrapperExpectation: &mocks.Expectation{
				MethodName:      "Run",
				Arguments:       []interface{}{"docker.io/library/mongo@sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e", "/tmp/.docker"},
				ReturnArguments: []interface{}{microScannerReport, nil},
			},
			TransformerExpectation: &mocks.Expectation{
				MethodName:      "Transform",
				Arguments:       []interface{}{microScannerReport},
				ReturnArguments: []interface{}{harborReport, nil},
			},
			DataStoreExpectations: []*mocks.Expectation{
				{
					MethodName:      "UpdateScanJobStatus",
					Arguments:       []interface{}{scanID, job.Queued, job.Pending},
					ReturnArguments: []interface{}{nil},
				},
				{
					MethodName:      "SaveScanReports",
					Arguments:       []interface{}{scanID, scanReports},
					ReturnArguments: []interface{}{nil},
				},
				{
					MethodName:      "UpdateScanJobStatus",
					Arguments:       []interface{}{scanID, job.Pending, job.Finished},
					ReturnArguments: []interface{}{nil},
				},
			},
			ExpectedError: nil,
		},
		{
			Name: "Should return error when scan ID is not a valid UUID",
			ScanRequest: harbor.ScanRequest{
				ID: "INVALID_UUID",
			},
			ExpectedError: errors.New("parsing scan request ID: invalid UUID length: 12"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.Skip != nil {
				t.Skip(*tc.Skip)
			}

			authorizer := mocks.NewAuthorizer()
			wrapper := mocks.NewWrapper()
			transformer := mocks.NewTransformer()
			dataStore := mocks.NewDataStore()

			mocks.ApplyExpectations(t, authorizer, tc.AuthorizerExpectation)
			mocks.ApplyExpectations(t, wrapper, tc.WrapperExpectation)
			mocks.ApplyExpectations(t, transformer, tc.TransformerExpectation)
			mocks.ApplyExpectations(t, dataStore, tc.DataStoreExpectations...)

			scanner := NewScanner(authorizer, wrapper, transformer, dataStore)

			err := scanner.Scan(tc.ScanRequest)
			assert.Equal(t, tc.ExpectedError, err)

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
