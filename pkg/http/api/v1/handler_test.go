package v1

import (
	"errors"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/mocks"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/microscanner"
	"github.com/stretchr/testify/assert"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type Request struct {
	Method  string
	Target  string
	Body    io.Reader
	Headers http.Header
}

type Response struct {
	Code int
	Body string
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
			Body: "",
		},
	}}

	for _, td := range data {
		t.Run(td.Scenario, func(t *testing.T) {
			jobQueue := mocks.NewJobQueue()
			dataStore := mocks.NewDataStore()

			request := NewHTTPRequest(td.Request)
			response := httptest.NewRecorder()

			NewAPIHandler(jobQueue, dataStore).ServeHTTP(response, request)

			// then
			assert.Equal(t, td.Response.Code, response.Code)
			jobQueue.AssertExpectations(t)
			dataStore.AssertExpectations(t)
		})
	}
}

func TestRequestHandler_AcceptScanRequest(t *testing.T) {
	scanRequest := harbor.ScanRequest{
		Registry: harbor.Registry{
			URL:           "https://core.harbor.domain",
			Authorization: "Bearer: SECRET",
		},
		Artifact: harbor.Artifact{
			Repository: "library/mongo",
			Digest:     "sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e",
		},
	}

	scanRequestJSON := `{
  "id": "ABC",
  "registry": {
    "url": "https://core.harbor.domain",
    "authorization": "Bearer: SECRET"
  },
  "artifact": {
    "repository": "library/mongo",
    "digest": "sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e"
  }
}
`

	testCases := []struct {
		Name                string
		Request             Request
		JobQueueExpectation *mocks.Expectation

		ExpectedHTTPStatus int
		ExpectedResponse   string
	}{
		{
			Name: "Should accept a scan request",
			Request: Request{
				Method:  http.MethodPost,
				Target:  "/api/v1/scan",
				Body:    strings.NewReader(scanRequestJSON),
				Headers: map[string][]string{HeaderContentType: {mimeTypeScanRequest}},
			},
			JobQueueExpectation: &mocks.Expectation{
				MethodName:      "EnqueueScanJob",
				Arguments:       []interface{}{scanRequest},
				ReturnArguments: []interface{}{&job.ScanJob{ID: "job:123"}, nil},
			},
			ExpectedHTTPStatus: http.StatusAccepted,
			ExpectedResponse:   `{"id": "job:123"}`,
		},
		{
			Name: "Should return error when enqueuing scan job fails",
			Request: Request{
				Method:  http.MethodPost,
				Target:  "/api/v1/scan",
				Body:    strings.NewReader(scanRequestJSON),
				Headers: map[string][]string{HeaderContentType: {mimeTypeScanRequest}},
			}, JobQueueExpectation: &mocks.Expectation{
				MethodName:      "EnqueueScanJob",
				Arguments:       []interface{}{scanRequest},
				ReturnArguments: []interface{}{(*job.ScanJob)(nil), errors.New("queue failed")},
			},
			ExpectedHTTPStatus: http.StatusInternalServerError,
			ExpectedResponse:   `{"error": {"message": "enqueuing scan job: queue failed"}}`,
		},
		{
			Name: "Should return error when scan request cannot be parsed",
			Request: Request{
				Method:  http.MethodPost,
				Target:  "/api/v1/scan",
				Body:    strings.NewReader("THIS AIN'T PARSE"),
				Headers: map[string][]string{HeaderContentType: {mimeTypeScanRequest}},
			},
			ExpectedHTTPStatus: http.StatusBadRequest,
			ExpectedResponse:   `{"error": {"message": "unmarshalling scan request: invalid character 'T' looking for beginning of value"}}`,
		},
		{
			Name: "Should return error when scan request cannot be processed",
			Request: Request{
				Method:  http.MethodPost,
				Target:  "/api/v1/scan",
				Body:    strings.NewReader(`{"id": "ABC", "registry": {"url": "INVALID URL"}}`),
				Headers: map[string][]string{HeaderContentType: {mimeTypeScanRequest}},
			},
			ExpectedHTTPStatus: http.StatusUnprocessableEntity,
			ExpectedResponse:   `{"error": {"message": "invalid registry.url"}}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			jobQueue := mocks.NewJobQueue()
			dataStore := mocks.NewDataStore()

			mocks.ApplyExpectations(t, jobQueue, tc.JobQueueExpectation)

			request := NewHTTPRequest(tc.Request)
			response := httptest.NewRecorder()

			NewAPIHandler(jobQueue, dataStore).ServeHTTP(response, request)

			assert.Equal(t, tc.ExpectedHTTPStatus, response.Code)
			if tc.ExpectedResponse != "" {
				assert.JSONEq(t, tc.ExpectedResponse, response.Body.String())
			}

			jobQueue.AssertExpectations(t)
			dataStore.AssertExpectations(t)
		})
	}
}

func TestRequestHandler_ValidateScanRequest(t *testing.T) {
	testCases := []struct {
		Name          string
		Request       harbor.ScanRequest
		ExpectedError *harbor.Error
	}{
		{
			Name:    "Should return error when Registry URL is blank",
			Request: harbor.ScanRequest{},
			ExpectedError: &harbor.Error{
				HTTPCode: http.StatusUnprocessableEntity,
				Message:  "missing registry.url",
			},
		},
		{
			Name: "Should return error when Registry URL is invalid",
			Request: harbor.ScanRequest{
				Registry: harbor.Registry{
					URL: "INVALID URL",
				},
			},
			ExpectedError: &harbor.Error{
				HTTPCode: http.StatusUnprocessableEntity,
				Message:  "invalid registry.url",
			},
		},
		{
			Name: "Should return error when artifact repository is blank",
			Request: harbor.ScanRequest{
				Registry: harbor.Registry{
					URL: "https://core.harbor.domain",
				},
			},
			ExpectedError: &harbor.Error{
				HTTPCode: http.StatusUnprocessableEntity,
				Message:  "missing artifact.repository",
			},
		},
		{
			Name: "Should return error when artifact digest is blank",
			Request: harbor.ScanRequest{
				Registry: harbor.Registry{
					URL: "https://core.harbor.domain",
				},
				Artifact: harbor.Artifact{
					Repository: "library/mongo",
				},
			},
			ExpectedError: &harbor.Error{
				HTTPCode: http.StatusUnprocessableEntity,
				Message:  "missing artifact.digest",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			handler := requestHandler{}
			validationError := handler.ValidateScanRequest(tc.Request)
			assert.Equal(t, tc.ExpectedError, validationError)
		})
	}
}

func TestRequestHandler_GetScanReport(t *testing.T) {
	generatedAt, _ := time.Parse(time.RFC3339, "2019-09-23T13:51:29.466573+02:00")

	scanRequestID := "job:123"
	harborReport := &harbor.VulnerabilityReport{
		GeneratedAt: generatedAt,
		Artifact: harbor.Artifact{
			Repository: "library/mongo",
			Digest:     "sha256:72d3540a294b8718b228e71e0ca9c2c079c936decfc0703eb42f8b0d0288af07",
		},
		Scanner: harbor.Scanner{
			Name:    "MicroScanner",
			Vendor:  "Aqua Security",
			Version: "3.0.5",
		},
		Severity: harbor.SevHigh,
		Vulnerabilities: []harbor.VulnerabilityItem{
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
  "generated_at": "2019-09-23T13:51:29.466573+02:00",
  "artifact": {
    "repository": "library/mongo",
    "digest": "sha256:72d3540a294b8718b228e71e0ca9c2c079c936decfc0703eb42f8b0d0288af07"
  },
  "scanner": {
    "name": "MicroScanner",
    "vendor": "Aqua Security",
    "version": "3.0.5"
  },
  "severity": "High",
  "vulnerabilities": [
    {
      "id": "CVE-2016-2781",
      "severity": "High",
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

	testCases := []struct {
		Scenario             string
		Skip                 bool
		Request              Request
		Response             Response
		DataStoreExpectation []*mocks.Expectation
	}{
		{
			Scenario: "Should return 404 Not Found when scan job is nil",
			Request: Request{
				Method: http.MethodGet,
				Target: fmt.Sprintf("/api/v1/scan/%s/report", scanRequestID),
			},
			DataStoreExpectation: []*mocks.Expectation{
				{
					MethodName:      "GetScanJob",
					Arguments:       []interface{}{scanRequestID},
					ReturnArguments: []interface{}{(*job.ScanJob)(nil), nil},
				},
			},
			Response: Response{
				Code: http.StatusNotFound,
				Body: `{"error": {"message": "cannot find scan job: job:123"}}`,
			},
		},
		{
			Scenario: fmt.Sprintf("Should return 302 Found status when scan job is %s", job.Queued),
			Request: Request{
				Method: http.MethodGet,
				Target: fmt.Sprintf("/api/v1/scan/%s/report", scanRequestID),
			},
			DataStoreExpectation: []*mocks.Expectation{
				{
					MethodName:      "GetScanJob",
					Arguments:       []interface{}{scanRequestID},
					ReturnArguments: []interface{}{&job.ScanJob{Status: job.Queued}, nil},
				},
			},
			Response: Response{
				Code: http.StatusFound,
			},
		},
		{
			Scenario: fmt.Sprintf("Should return 302 Found status when scan job is %s", job.Pending),
			Request: Request{
				Method: http.MethodGet,
				Target: fmt.Sprintf("/api/v1/scan/%s/report", scanRequestID),
			},
			DataStoreExpectation: []*mocks.Expectation{
				{
					MethodName:      "GetScanJob",
					Arguments:       []interface{}{scanRequestID},
					ReturnArguments: []interface{}{&job.ScanJob{Status: job.Pending}, nil},
				},
			},
			Response: Response{
				Code: http.StatusFound,
			},
		},
		{
			Scenario: fmt.Sprintf("Should return 500 Internal Server Error when scan job is %s", job.Failed),
			Request: Request{
				Method: http.MethodGet,
				Target: fmt.Sprintf("/api/v1/scan/%s/report", scanRequestID),
			},
			DataStoreExpectation: []*mocks.Expectation{
				{
					MethodName: "GetScanJob",
					Arguments:  []interface{}{scanRequestID},
					ReturnArguments: []interface{}{
						&job.ScanJob{
							Status: job.Failed,
							Error:  "it failed badly",
						}, nil},
				},
			},
			Response: Response{
				Code: http.StatusInternalServerError,
				Body: `{"error": {"message": "it failed badly"}}`,
			},
		},
		{
			Scenario: "Should return 500 Internal Server Error when scan job has unknown status",
			Request: Request{
				Method: http.MethodGet,
				Target: fmt.Sprintf("/api/v1/scan/%s/report", scanRequestID),
			},
			DataStoreExpectation: []*mocks.Expectation{
				{
					MethodName: "GetScanJob",
					Arguments:  []interface{}{scanRequestID},
					ReturnArguments: []interface{}{
						&job.ScanJob{
							ID:     "job:123",
							Status: -1,
						}, nil},
				},
			},
			Response: Response{
				Code: http.StatusInternalServerError,
				Body: `{"error": {"message": "unexpected status Unknown of scan job job:123"}}`,
			},
		},
		{
			Scenario: "Should return HarborVulnerabilityReport when report MIME type is specified",
			Request: Request{
				Method: http.MethodGet,
				Target: fmt.Sprintf("/api/v1/scan/%s/report", scanRequestID),
				Headers: map[string][]string{
					headerAccept: {mimeTypeHarborVulnerabilityReport},
				},
			},
			DataStoreExpectation: []*mocks.Expectation{
				{
					MethodName: "GetScanJob",
					Arguments:  []interface{}{scanRequestID},
					ReturnArguments: []interface{}{
						&job.ScanJob{
							ID:     scanRequestID,
							Status: job.Finished,
							Reports: &job.ScanReports{
								HarborVulnerabilityReport: harborReport,
							},
						},
						nil,
					},
				},
			},
			Response: Response{
				Code: http.StatusOK,
				Body: harborReportJSON,
			},
		},
		{
			Scenario: "Should return HarborVulnerabilityReport when report MIME type is not specified",
			Request: Request{
				Method:  http.MethodGet,
				Target:  fmt.Sprintf("/api/v1/scan/%s/report", scanRequestID),
				Headers: map[string][]string{},
			},
			DataStoreExpectation: []*mocks.Expectation{
				{
					MethodName: "GetScanJob",
					Arguments:  []interface{}{scanRequestID},
					ReturnArguments: []interface{}{
						&job.ScanJob{
							ID:     scanRequestID,
							Status: job.Finished,
							Reports: &job.ScanReports{
								HarborVulnerabilityReport: harborReport,
							},
						},
						nil,
					},
				},
			},
			Response: Response{
				Code: http.StatusOK,
				Body: harborReportJSON,
			},
		},
		{
			Scenario: "Should return MicroScannerReport",
			Request: Request{
				Method: http.MethodGet,
				Target: fmt.Sprintf("/api/v1/scan/%s/report", scanRequestID),
				Headers: map[string][]string{
					headerAccept: {mimeTypeMicroScannerReport},
				},
			},
			DataStoreExpectation: []*mocks.Expectation{
				{
					MethodName: "GetScanJob",
					Arguments:  []interface{}{scanRequestID},
					ReturnArguments: []interface{}{
						&job.ScanJob{
							ID:     scanRequestID,
							Status: job.Finished,
							Reports: &job.ScanReports{
								MicroScannerReport: microScannerReport,
							},
						},
						nil},
				},
			},
			Response: Response{
				Code: http.StatusOK,
				Body: microScannerReportJSON,
			},
		},
		{
			Scenario: "Should return error when MIME type is unknown",
			Request: Request{
				Method: http.MethodGet,
				Target: fmt.Sprintf("/api/v1/scan/%s/report", scanRequestID),
				Headers: map[string][]string{
					headerAccept: {"UNKNOWN_MIME_TYPE"},
				},
			},
			DataStoreExpectation: []*mocks.Expectation{
				{
					MethodName: "GetScanJob",
					Arguments:  []interface{}{scanRequestID},
					ReturnArguments: []interface{}{
						&job.ScanJob{
							ID:     scanRequestID,
							Status: job.Finished,
						},
						nil},
				},
			},
			Response: Response{
				Code: http.StatusUnprocessableEntity,
				Body: `{"error": {"message": "unrecognized report MIME type: UNKNOWN_MIME_TYPE"}}`,
			},
		},
	}

	for _, td := range testCases {
		t.Run(td.Scenario, func(t *testing.T) {
			if td.Skip {
				t.Skip()
			}

			jobQueue := mocks.NewJobQueue()
			dataStore := mocks.NewDataStore()

			mocks.ApplyExpectations(t, dataStore, td.DataStoreExpectation...)

			request := NewHTTPRequest(td.Request)
			response := httptest.NewRecorder()

			NewAPIHandler(jobQueue, dataStore).ServeHTTP(response, request)

			assert.Equal(t, td.Response.Code, response.Code)
			if td.Response.Body != "" {
				assert.JSONEq(t, td.Response.Body, response.Body.String())
			}

			jobQueue.AssertExpectations(t)
			dataStore.AssertExpectations(t)
		})
	}

}

func NewHTTPRequest(request Request) *http.Request {
	httpRequest := httptest.NewRequest(request.Method, request.Target, request.Body)
	for key, values := range request.Headers {
		for _, value := range values {
			httpRequest.Header.Set(key, value)
		}
	}
	return httpRequest
}
