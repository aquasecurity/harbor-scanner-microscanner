package v1

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/store"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"net/http"
	"net/url"
	"strings"
)

const (
	headerAccept       = "Accept"
	headerRefreshAfter = "Refresh-After"

	mimeTypeMetadata                  = "application/vnd.scanner.adapter.metadata+json; version=1.0"
	mimeTypeScanRequest               = "application/vnd.scanner.adapter.scan.request+json; version=1.0"
	mimeTypeScanResponse              = "application/vnd.scanner.adapter.scan.response+json; version=1.0"
	mimeTypeHarborVulnerabilityReport = "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
	mimeTypeMicroScannerReport        = "application/vnd.scanner.adapter.vuln.report.raw"

	pathAPIPrefix        = "/api/v1"
	pathMetadata         = "/metadata"
	pathScan             = "/scan"
	pathScanReport       = "/scan/{scan_request_id}/report"
	pathVarScanRequestID = "scan_request_id"

	fieldScanJobID = "scan_job_id"
)

type requestHandler struct {
	jobQueue  job.Queue
	dataStore store.DataStore
	BaseHandler
}

func NewAPIHandler(jobQueue job.Queue, dataStore store.DataStore) http.Handler {
	handler := &requestHandler{
		jobQueue:  jobQueue,
		dataStore: dataStore,
	}

	router := mux.NewRouter()
	v1Router := router.PathPrefix(pathAPIPrefix).Subrouter()

	v1Router.Methods(http.MethodGet).Path(pathMetadata).HandlerFunc(handler.GetMetadata)
	v1Router.Methods(http.MethodPost).Path(pathScan).HandlerFunc(handler.AcceptScanRequest)
	v1Router.Methods(http.MethodGet).Path(pathScanReport).HandlerFunc(handler.GetScanReport)
	return router
}

func (h *requestHandler) GetMetadata(res http.ResponseWriter, req *http.Request) {
	md := &harbor.ScannerMetadata{
		Scanner: harbor.Scanner{
			Name:    "MicroScanner",
			Vendor:  "Aqua Security",
			Version: "3.0.5",
		},
		Capabilities: []*harbor.Capability{
			{
				ConsumesMIMETypes: []string{
					"application/vnd.oci.image.manifest.v1+json",
					"application/vnd.docker.distribution.manifest.v2+json",
				},
				ProducesMIMETypes: []string{
					mimeTypeHarborVulnerabilityReport,
					mimeTypeMicroScannerReport,
				},
			},
		},
		Properties: map[string]string{
			"harbor.scanner-adapter/scanner-type":                      "os-package-vulnerability",
			"harbor.scanner-adapter/vulnerability-database-updated-at": "",
		},
	}

	res.Header().Set(HeaderContentType, mimeTypeMetadata)
	err := json.NewEncoder(res).Encode(md)
	if err != nil {
		log.Errorf("Error while marshalling metadata response: %v", err)
		h.SendInternalServerError(res)
	}
}

func (h *requestHandler) AcceptScanRequest(res http.ResponseWriter, req *http.Request) {
	log.Debug("Accept scan request received")
	scanRequest := harbor.ScanRequest{}
	err := json.NewDecoder(req.Body).Decode(&scanRequest)
	if err != nil {
		log.WithError(err).Error("Error while unmarshalling scan request")
		h.SendJSONError(res, harbor.Error{
			HTTPCode: http.StatusBadRequest,
			Message:  fmt.Sprintf("unmarshalling scan request: %s", err.Error()),
		})
		return
	}

	if validationError := h.ValidateScanRequest(scanRequest); validationError != nil {
		log.Errorf("Error while validating scan request: %s", validationError.Message)
		h.SendJSONError(res, *validationError)
		return
	}

	scanJob, err := h.jobQueue.EnqueueScanJob(scanRequest)
	if err != nil {
		log.WithError(err).Error("Error while enqueuing scan job")
		h.SendJSONError(res, harbor.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("enqueuing scan job: %s", err.Error()),
		})
		return
	}
	log.WithField(fieldScanJobID, scanJob.ID).Debug("Scan job enqueued successfully")

	res.Header().Set(HeaderContentType, mimeTypeScanResponse)
	res.WriteHeader(http.StatusAccepted)

	err = json.NewEncoder(res).Encode(harbor.ScanResponse{ID: scanJob.ID})
	if err != nil {
		log.Errorf("Error while marshalling scan response: %v", err)
		h.SendJSONError(res, harbor.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("marshaling scan response: %s", err.Error()),
		})
		return
	}
}

func (h *requestHandler) ValidateScanRequest(req harbor.ScanRequest) *harbor.Error {
	if req.Registry.URL == "" {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "missing registry.url",
		}
	}

	_, err := url.ParseRequestURI(req.Registry.URL)
	if err != nil {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "invalid registry.url",
		}
	}

	if req.Artifact.Repository == "" {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "missing artifact.repository",
		}
	}

	if req.Artifact.Digest == "" {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "missing artifact.digest",
		}
	}

	return nil
}

func (h *requestHandler) GetScanReport(res http.ResponseWriter, req *http.Request) {
	log.Debug("Get scan report request received")
	vars := mux.Vars(req)
	scanJobID, ok := vars[pathVarScanRequestID]
	if !ok {
		log.Error("Error while parsing `scan_request_id` path variable")
		h.SendJSONError(res, harbor.Error{
			HTTPCode: http.StatusBadRequest,
			Message:  "missing scan_request_id",
		})
		return
	}

	reqLog := log.WithField("scan_job_id", scanJobID)

	scanJob, err := h.dataStore.GetScanJob(scanJobID)
	if scanJob == nil {
		reqLog.Error("Cannot find scan job")
		h.SendJSONError(res, harbor.Error{
			HTTPCode: http.StatusNotFound,
			Message:  fmt.Sprintf("cannot find scan job: %v", scanJobID),
		})
		return
	}

	if scanJob.Status == job.Queued || scanJob.Status == job.Pending {
		reqLog.WithField("scan_job_status", scanJob.Status).Debug("Scan job has not finished yet")
		res.Header().Set(headerRefreshAfter, "15")
		res.WriteHeader(http.StatusFound)
		return
	}

	if scanJob.Status == job.Failed {
		reqLog.WithField(log.ErrorKey, scanJob.Error).Error("Scan job failed")
		h.SendJSONError(res, harbor.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  scanJob.Error,
		})
		return
	}

	if scanJob.Status != job.Finished {
		reqLog.WithField("scan_job_status", scanJob.Status).Error("Unexpected scan job status")
		h.SendJSONError(res, harbor.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("unexpected status %v of scan job %v", scanJob.Status, scanJob.ID),
		})
		return
	}

	switch reportMIMEType := h.GetReportMIMEType(req); reportMIMEType {
	case mimeTypeHarborVulnerabilityReport, "":
		res.Header().Set(HeaderContentType, reportMIMEType)
		err = json.NewEncoder(res).Encode(scanJob.Reports.HarborVulnerabilityReport)
		if err != nil {
			reqLog.WithError(err).Error("Error while marshalling Harbor vulnerability report")
			h.SendJSONError(res, harbor.Error{
				HTTPCode: http.StatusInternalServerError,
				Message:  fmt.Sprintf("marshalling Harbor vulnerability report: %v", err),
			})
		}
	case mimeTypeMicroScannerReport:
		res.Header().Set(HeaderContentType, reportMIMEType)
		err = json.NewEncoder(res).Encode(scanJob.Reports.MicroScannerReport)
		if err != nil {
			reqLog.WithError(err).Error("Error while marshalling MicroScanner report")
			h.SendJSONError(res, harbor.Error{
				HTTPCode: http.StatusInternalServerError,
				Message:  fmt.Sprintf("marshalling MicroScanner report: %v", err),
			})
		}
	default:
		reqLog.Errorf("Unrecognized report MIME type: %v", reportMIMEType)
		h.SendJSONError(res, harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  fmt.Sprintf("unrecognized report MIME type: %v", reportMIMEType),
		})
	}
}

func (h *requestHandler) GetReportMIMEType(req *http.Request) string {
	return strings.TrimSpace(req.Header.Get(headerAccept))
}
