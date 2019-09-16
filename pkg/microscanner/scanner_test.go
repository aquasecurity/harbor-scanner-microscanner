package microscanner

import (
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/mocks"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/microscanner"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"path/filepath"
	"testing"
)

func TestScanner_Scan(t *testing.T) {
	tmpDir, err := ioutil.TempDir("", "test")
	configFileName := filepath.Join(tmpDir, "config.json")

	require.NoError(t, err)
	scanID := "job:123"
	scanRequest := harbor.ScanRequest{
		Registry: harbor.Registry{
			URL: "https://core.harbor.domain:433",
		},
		Artifact: harbor.Artifact{
			Repository: "library/mongo",
			Digest:     "sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e",
		},
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
				ReturnArguments: []interface{}{configFileName, nil},
			},
			WrapperExpectation: &mocks.Expectation{
				MethodName:      "Run",
				Arguments:       []interface{}{"core.harbor.domain:433/library/mongo@sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e", configFileName},
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

			err := scanner.Scan(scanID, tc.ScanRequest)
			assert.Equal(t, tc.ExpectedError, err)

			authorizer.AssertExpectations(t)
			wrapper.AssertExpectations(t)
			transformer.AssertExpectations(t)
			dataStore.AssertExpectations(t)
		})
	}

}

func TestScanner_ToImageRef(t *testing.T) {
	testCases := []struct {
		Request  harbor.ScanRequest
		ImageRef string
	}{
		{
			Request: harbor.ScanRequest{
				Registry: harbor.Registry{
					URL: "https://core.harbor.domain",
				},
				Artifact: harbor.Artifact{
					Repository: "library/mongo",
					Digest:     "test:ABC",
				},
			},
			ImageRef: "core.harbor.domain/library/mongo@test:ABC",
		},
		{
			Request: harbor.ScanRequest{
				Registry: harbor.Registry{
					URL: "https://core.harbor.domain:443",
				},
				Artifact: harbor.Artifact{Repository: "library/nginx",
					Digest: "test:DEF",
				},
			},
			ImageRef: "core.harbor.domain:443/library/nginx@test:DEF",
		},
		{
			Request: harbor.ScanRequest{
				Registry: harbor.Registry{
					URL: "http://harbor-harbor-registry:5000",
				},
				Artifact: harbor.Artifact{
					Repository: "scanners/mongo",
					Digest:     "test:GHI",
				},
			},
			ImageRef: "harbor-harbor-registry:5000/scanners/mongo@test:GHI",
		},
	}
	for _, tc := range testCases {
		s := scanner{}
		imageRef, err := s.ToImageRef(tc.Request)
		require.NoError(t, err)
		assert.Equal(t, tc.ImageRef, imageRef)
	}
}
