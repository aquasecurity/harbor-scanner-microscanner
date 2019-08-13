package v1

import (
	"fmt"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/microscanner"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/store"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type scannerMock struct {
	mock.Mock
}

func (m *scannerMock) GetMetadata() (*harbor.ScannerMetadata, error) {
	args := m.Called()
	return args.Get(0).(*harbor.ScannerMetadata), args.Error(1)
}

func (m *scannerMock) Scan(req harbor.ScanRequest) error {
	args := m.Called(req)
	return args.Error(0)
}

func (m *scannerMock) GetHarborVulnerabilityReport(scanRequestID string) (*harbor.VulnerabilityReport, error) {
	args := m.Called(scanRequestID)
	return args.Get(0).(*harbor.VulnerabilityReport), args.Error(1)
}

func (m *scannerMock) GetMicroScannerReport(scanRequestID string) (*microscanner.ScanReport, error) {
	args := m.Called(scanRequestID)
	return args.Get(0).(*microscanner.ScanReport), args.Error(1)
}

type jobQueueMock struct {
	mock.Mock
}

func (m *jobQueueMock) Start() {
	m.Called()
}

func (m *jobQueueMock) Stop() {
	m.Called()
}

func (m *jobQueueMock) EnqueueScanJob(sr harbor.ScanRequest) (string, error) {
	args := m.Called(sr)
	return args.String(0), args.Error(1)
}

type dataStoreMock struct {
	mock.Mock
}

func (m *dataStoreMock) SaveScan(scanID uuid.UUID, scan *store.Scan) error {
	args := m.Called(scanID)
	return args.Error(0)
}

func (m *dataStoreMock) GetScan(scanID uuid.UUID) (*store.Scan, error) {
	args := m.Called(scanID)
	return args.Get(0).(*store.Scan), args.Error(1)
}

type Request struct {
	Method  string
	Target  string
	Headers http.Header
}

type Response struct {
	Code int
	Body *string
}

type Expectation struct {
	MethodName      string
	Arguments       []interface{}
	ReturnArguments []interface{}
}

func TestRequestHandler_GetHealth(t *testing.T) {
	// given
	scanner := new(scannerMock)
	jobQueue := new(jobQueueMock)
	dataStore := new(dataStoreMock)
	handler := NewAPIHandler(scanner, jobQueue, dataStore)
	// and
	request := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
	response := httptest.NewRecorder()

	// when
	handler.ServeHTTP(response, request)

	// then
	assert.Equal(t, http.StatusOK, response.Code)

	scanner.AssertExpectations(t)
	jobQueue.AssertExpectations(t)
}

func TestRequestHandler_GetMetadata(t *testing.T) {
	metadata := &harbor.ScannerMetadata{
		Name: "MicroScanner",
	}

	data := []struct {
		Scenario           string
		Request            Request
		ScannerExpectation *Expectation
		Response           Response
	}{{
		Scenario: "Should return metadata",
		Request: Request{
			Method: http.MethodGet,
			Target: "/api/v1/metadata",
		},
		ScannerExpectation: &Expectation{
			MethodName:      "GetMetadata",
			Arguments:       []interface{}{},
			ReturnArguments: []interface{}{metadata, nil},
		},
		Response: Response{
			Code: http.StatusOK,
			Body: nil,
		},
	}}

	for _, td := range data {
		t.Run(td.Scenario, func(t *testing.T) {
			scanner := new(scannerMock)
			jobQueue := new(jobQueueMock)
			dataStore := new(dataStoreMock)
			if expectation := td.ScannerExpectation; expectation != nil {
				scanner.On(expectation.MethodName, expectation.Arguments...).
					Return(expectation.ReturnArguments...)
			}
			// and
			handler := NewAPIHandler(scanner, jobQueue, dataStore)
			// and
			request := NewHTTPRequest(td.Request)
			response := httptest.NewRecorder()

			// when
			handler.ServeHTTP(response, request)

			// then
			assert.Equal(t, td.Response.Code, response.Code)
			scanner.AssertExpectations(t)
			jobQueue.AssertExpectations(t)
		})
	}
}

func TestRequestHandler_AcceptScanRequest(t *testing.T) {
	scanner := new(scannerMock)
	jobQueue := new(jobQueueMock)
	dataStore := new(dataStoreMock)

	jobQueue.On("EnqueueScanJob", harbor.ScanRequest{
		ID:                    "ABC",
		RegistryURL:           "docker.io",
		RegistryAuthorization: "Bearer: SECRET",
		ArtifactRepository:    "library/mongo",
		ArtifactDigest:        "sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e",
	}).Return("job:123", nil)

	handler := NewAPIHandler(scanner, jobQueue, dataStore)

	scanRequest := `{
  "id": "ABC",
  "registry_url": "docker.io",
  "registry_authorization": "Bearer: SECRET",
  "artifact_repository": "library/mongo",
  "artifact_digest": "sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e"
}
`

	request := httptest.NewRequest(http.MethodPost, "/api/v1/scan", strings.NewReader(scanRequest))
	request.Header.Set(headerContentType, mimeTypeScanRequest)
	response := httptest.NewRecorder()

	// when
	handler.ServeHTTP(response, request)

	// then
	assert.Equal(t, http.StatusAccepted, response.Code)

	scanner.AssertExpectations(t)
	jobQueue.AssertExpectations(t)
}

func TestRequestHandler_GetScanReport(t *testing.T) {

	scanRequestID := uuid.New()
	harborReport := &harbor.VulnerabilityReport{
		Severity: harbor.SevHigh,
		Vulnerabilities: []*harbor.VulnerabilityItem{
			{
				ID:          "CVE-2016-2781",
				Severity:    harbor.SevHigh,
				Pkg:         "coreutils",
				Version:     "8.25-2ubuntu3~16.04",
				Description: "(...)",
				Links: []string{
					"https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-2781",
				},
			},
		},
	}
	harborReportJSON := `{
  "severity": 5,
  "vulnerabilities": [
    {
      "id": "CVE-2016-2781",
      "severity": 5,
      "package": "coreutils",
      "version": "8.25-2ubuntu3~16.04",
      "description": "(...)",
      "links": [
        "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-2781"
      ]
    }
  ]
}`
	microScannerReport := &microscanner.ScanReport{
		Digest:  "72d3540a294b8718b228e71e0ca9c2c079c936decfc0703eb42f8b0d0288af07",
		OS:      "ubuntu",
		Version: "16.04",
		Resources: []microscanner.ResourceScan{
			{
				Resource: microscanner.Resource{
					Format:   "deb",
					Name:     "coreutils",
					Version:  "8.25-2ubuntu3~16.04",
					Arch:     "amd64",
					CPE:      "pkg:/ubuntu:16.04:coreutils:8.25-2ubuntu3~16.04",
					NameHash: "f54228fe7e2ccf1df47e1d377fd167b6",
					License:  "",
				},
				Scanned: true,
				Vulnerabilities: []microscanner.Vulnerability{
					{
						Name:             "CVE-2016-2781",
						Description:      "(...)",
						VendorURL:        "https://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-2781.html",
						VendorSeverity:   "low",
						VendorSeverityV3: "medium",
						Classification:   "",
						FixVersion:       "any in ubuntu 16.10",
						NVDURL:           "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-2781",
						NVDSeverity:      "low",
						NVDSeverityV3:    "medium",
					},
				},
			},
		},
	}
	microScannerReportJSON := `{
  "digest": "72d3540a294b8718b228e71e0ca9c2c079c936decfc0703eb42f8b0d0288af07",
  "os": "ubuntu",
  "version": "16.04",
  "vulnerability_summary":null,
  "resources": [
    {
      "resource": {
        "format": "deb",
        "name": "coreutils",
        "version": "8.25-2ubuntu3~16.04",
        "arch": "amd64",
        "cpe": "pkg:/ubuntu:16.04:coreutils:8.25-2ubuntu3~16.04",
        "name_hash": "f54228fe7e2ccf1df47e1d377fd167b6",
        "license": ""
      },
      "scanned": true,
      "vulnerabilities": [
        {
          "name": "CVE-2016-2781",
          "description": "(...)",
          "vendor_url": "https://people.canonical.com/~ubuntu-security/cve/2016/CVE-2016-2781.html",
          "vendor_severity": "low",
          "vendor_severity_v3": "medium",
          "classification": "",
          "fix_version": "any in ubuntu 16.10",
          "nvd_url": "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2016-2781",
          "nvd_severity": "low",
          "nvd_severity_v3": "medium"
        }
      ]
    }
  ]
}`

	data := []struct {
		Scenario             string
		Skip                 bool
		Request              Request
		Response             Response
		DataStoreExpectation *Expectation
		ScannerExpectation   *Expectation
	}{
		{
			Scenario: "Should return HarborVulnerabilityReport when report MIME type is specified",
			Request: Request{
				Method: http.MethodGet,
				Target: fmt.Sprintf("/api/v1/scan/%s/report", scanRequestID.String()),
				Headers: map[string][]string{
					headerAccept: {mimeTypeHarborVulnReport},
				},
			},
			DataStoreExpectation: &Expectation{
				MethodName: "GetScan",
				Arguments:  []interface{}{scanRequestID},
				ReturnArguments: []interface{}{&store.Scan{
					JobID: "128",
				}, nil},
			},
			ScannerExpectation: &Expectation{
				MethodName:      "GetHarborVulnerabilityReport",
				Arguments:       []interface{}{scanRequestID.String()},
				ReturnArguments: []interface{}{harborReport, nil},
			},
			Response: Response{
				Code: http.StatusOK,
				Body: stringptr(harborReportJSON),
			},
		},
		{
			Scenario: "Should return HarborVulnerabilityReport when report MIME type is not specified",
			Request: Request{
				Method:  http.MethodGet,
				Target:  fmt.Sprintf("/api/v1/scan/%s/report", scanRequestID.String()),
				Headers: map[string][]string{},
			},
			DataStoreExpectation: &Expectation{
				MethodName: "GetScan",
				Arguments:  []interface{}{scanRequestID},
				ReturnArguments: []interface{}{&store.Scan{
					JobID: "128",
				}, nil},
			},
			ScannerExpectation: &Expectation{
				MethodName:      "GetHarborVulnerabilityReport",
				Arguments:       []interface{}{scanRequestID.String()},
				ReturnArguments: []interface{}{harborReport, nil},
			},
			Response: Response{
				Code: http.StatusOK,
				Body: stringptr(harborReportJSON),
			},
		},
		{
			Scenario: "Should return MicroScannerReport",
			Skip:     true,
			Request: Request{
				Method: http.MethodGet,
				Target: "/api/v1/scan/ABC/report",
				Headers: map[string][]string{
					headerAccept: {mimeTypeMicroScannerReport},
				},
			},
			ScannerExpectation: &Expectation{
				MethodName:      "GetMicroScannerReport",
				Arguments:       []interface{}{"ABC"},
				ReturnArguments: []interface{}{microScannerReport, nil},
			},
			Response: Response{
				Code: http.StatusOK,
				Body: stringptr(microScannerReportJSON),
			},
		},
		{
			Scenario: "Should return 422 error when report MIME type cannot be recognized",
			Skip:     true,
			Request: Request{
				Method: http.MethodGet,
				Target: "/api/v1/scan/ABC/report",
				Headers: map[string][]string{
					headerAccept: {"application/vnd.scanner.adapter.unknown.report+json"},
				},
			},
			Response: Response{
				Code: http.StatusUnprocessableEntity,
			},
		},
	}

	for _, td := range data {
		t.Run(td.Scenario, func(t *testing.T) {
			if td.Skip {
				t.Skip()
			}

			scanner := new(scannerMock)
			jobQueue := new(jobQueueMock)
			dataStore := new(dataStoreMock)

			if expectation := td.DataStoreExpectation; expectation != nil {
				dataStore.On(expectation.MethodName, expectation.Arguments...).
					Return(expectation.ReturnArguments...)
			}

			if expectation := td.ScannerExpectation; expectation != nil {
				scanner.On(expectation.MethodName, expectation.Arguments...).
					Return(expectation.ReturnArguments...)
			}

			// and
			handler := NewAPIHandler(scanner, jobQueue, dataStore)
			// and
			request := NewHTTPRequest(td.Request)
			response := httptest.NewRecorder()

			// when
			handler.ServeHTTP(response, request)

			// then
			assert.Equal(t, td.Response.Code, response.Code)
			if td.Response.Body != nil {
				assert.JSONEq(t, *td.Response.Body, response.Body.String())
			}

			scanner.AssertExpectations(t)
			jobQueue.AssertExpectations(t)
			dataStore.AssertExpectations(t)
		})
	}

}

func NewHTTPRequest(request Request) *http.Request {
	httpRequest := httptest.NewRequest(request.Method, request.Target, nil)
	for key, values := range request.Headers {
		for _, value := range values {
			httpRequest.Header.Set(key, value)
		}
	}
	return httpRequest
}

func stringptr(val string) *string {
	return &val
}
