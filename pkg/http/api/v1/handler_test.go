package v1

import (
	"fmt"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/mocks"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/microscanner"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/store"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)


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
	scanner := mocks.NewScanner()
	jobQueue := mocks.NewJobQueue()
	dataStore := mocks.NewDataStore()
	handler := NewAPIHandler(jobQueue, dataStore)
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
	data := []struct {
		Scenario string
		Request  Request
		Response Response
	}{{
		Scenario: "Should return metadata",
		Request: Request{
			Method: http.MethodGet,
			Target: "/api/v1/metadata",
		},
		Response: Response{
			Code: http.StatusOK,
			Body: nil,
		},
	}}

	for _, td := range data {
		t.Run(td.Scenario, func(t *testing.T) {
			jobQueue := mocks.NewJobQueue()
			dataStore := mocks.NewDataStore()

			// and
			handler := NewAPIHandler(jobQueue, dataStore)
			// and
			request := NewHTTPRequest(td.Request)
			response := httptest.NewRecorder()

			// when
			handler.ServeHTTP(response, request)

			// then
			assert.Equal(t, td.Response.Code, response.Code)
			jobQueue.AssertExpectations(t)
			dataStore.AssertExpectations(t)
		})
	}
}

func TestRequestHandler_AcceptScanRequest(t *testing.T) {
	jobQueue := mocks.NewJobQueue()
	dataStore := mocks.NewDataStore()

	jobQueue.On("EnqueueScanJob", harbor.ScanRequest{
		ID:                    "ABC",
		RegistryURL:           "docker.io",
		RegistryAuthorization: "Bearer: SECRET",
		ArtifactRepository:    "library/mongo",
		ArtifactDigest:        "sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e",
	}).Return(&job.ScanJob{ID: "123"}, nil)

	handler := NewAPIHandler(jobQueue, dataStore)

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

	jobQueue.AssertExpectations(t)
	dataStore.AssertExpectations(t)
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

	var nilScanJob *job.ScanJob

	data := []struct {
		Scenario             string
		Skip                 bool
		Request              Request
		Response             Response
		JobQueueExpectation  *Expectation
		DataStoreExpectation *Expectation
	}{
		{
			Scenario: "Should return 404 Not Found when scan job is nil",
			Request: Request{
				Method: http.MethodGet,
				Target: fmt.Sprintf("/api/v1/scan/%s/report", scanRequestID.String()),
			},
			JobQueueExpectation: &Expectation{
				MethodName:      "GetScanJob",
				Arguments:       []interface{}{scanRequestID},
				ReturnArguments: []interface{}{nilScanJob, nil},
			},
			Response: Response{
				Code: http.StatusNotFound,
			},
		},
		{
			Scenario: fmt.Sprintf("Should return 302 Found status when scan job is %s", job.Queued),
			Request: Request{
				Method: http.MethodGet,
				Target: fmt.Sprintf("/api/v1/scan/%s/report", scanRequestID.String()),
			},
			JobQueueExpectation: &Expectation{
				MethodName:      "GetScanJob",
				Arguments:       []interface{}{scanRequestID},
				ReturnArguments: []interface{}{&job.ScanJob{Status: job.Queued}, nil},
			},
			Response: Response{
				Code: http.StatusFound,
			},
		},
		{
			Scenario: fmt.Sprintf("Should return 302 Found status when scan job is %s", job.Pending),
			Request: Request{
				Method: http.MethodGet,
				Target: fmt.Sprintf("/api/v1/scan/%s/report", scanRequestID.String()),
			},
			JobQueueExpectation: &Expectation{
				MethodName:      "GetScanJob",
				Arguments:       []interface{}{scanRequestID},
				ReturnArguments: []interface{}{&job.ScanJob{Status: job.Pending}, nil},
			},
			Response: Response{
				Code: http.StatusFound,
			},
		},
		{
			Scenario: fmt.Sprintf("Should return 500 Internal Server Error when scan job is %s", job.Failed),
			Request: Request{
				Method: http.MethodGet,
				Target: fmt.Sprintf("/api/v1/scan/%s/report", scanRequestID.String()),
			},
			JobQueueExpectation: &Expectation{
				MethodName:      "GetScanJob",
				Arguments:       []interface{}{scanRequestID},
				ReturnArguments: []interface{}{&job.ScanJob{Status: job.Failed}, nil},
			},
			Response: Response{
				Code: http.StatusInternalServerError,
			},
		},
		{
			Scenario: "Should return HarborVulnerabilityReport when report MIME type is specified",
			Request: Request{
				Method: http.MethodGet,
				Target: fmt.Sprintf("/api/v1/scan/%s/report", scanRequestID.String()),
				Headers: map[string][]string{
					headerAccept: {mimeTypeHarborVulnerabilityReport},
				},
			},
			JobQueueExpectation: &Expectation{
				MethodName:      "GetScanJob",
				Arguments:       []interface{}{scanRequestID},
				ReturnArguments: []interface{}{&job.ScanJob{Status: job.Finished}, nil},
			},
			DataStoreExpectation: &Expectation{
				MethodName: "GetScanReports",
				Arguments:  []interface{}{scanRequestID},
				ReturnArguments: []interface{}{&store.ScanReports{
					HarborVulnerabilityReport: harborReport,
				}, nil},
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
			JobQueueExpectation: &Expectation{
				MethodName:      "GetScanJob",
				Arguments:       []interface{}{scanRequestID},
				ReturnArguments: []interface{}{&job.ScanJob{Status: job.Finished}, nil},
			},
			DataStoreExpectation: &Expectation{
				MethodName: "GetScanReports",
				Arguments:  []interface{}{scanRequestID},
				ReturnArguments: []interface{}{&store.ScanReports{
					HarborVulnerabilityReport: harborReport,
				}, nil},
			},
			Response: Response{
				Code: http.StatusOK,
				Body: stringptr(harborReportJSON),
			},
		},
		{
			Scenario: "Should return MicroScannerReport",
			Request: Request{
				Method: http.MethodGet,
				Target: fmt.Sprintf("/api/v1/scan/%s/report", scanRequestID.String()),
				Headers: map[string][]string{
					headerAccept: {mimeTypeMicroScannerReport},
				},
			},
			JobQueueExpectation: &Expectation{
				MethodName:      "GetScanJob",
				Arguments:       []interface{}{scanRequestID},
				ReturnArguments: []interface{}{&job.ScanJob{Status: job.Finished}, nil},
			},
			DataStoreExpectation: &Expectation{
				MethodName: "GetScanReports",
				Arguments:  []interface{}{scanRequestID},
				ReturnArguments: []interface{}{&store.ScanReports{
					MicroScannerReport: microScannerReport,
				}, nil},
			},
			Response: Response{
				Code: http.StatusOK,
				Body: stringptr(microScannerReportJSON),
			},
		},
	}

	for _, td := range data {
		t.Run(td.Scenario, func(t *testing.T) {
			if td.Skip {
				t.Skip()
			}

			jobQueue := mocks.NewJobQueue()
			dataStore := mocks.NewDataStore()

			if expectation := td.JobQueueExpectation; expectation != nil {
				jobQueue.On(expectation.MethodName, expectation.Arguments...).
					Return(expectation.ReturnArguments...)
			}

			if expectation := td.DataStoreExpectation; expectation != nil {
				dataStore.On(expectation.MethodName, expectation.Arguments...).
					Return(expectation.ReturnArguments...)
			}

			// and
			handler := NewAPIHandler(jobQueue, dataStore)
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
