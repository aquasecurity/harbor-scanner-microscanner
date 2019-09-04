package v1

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/store"
	"github.com/google/uuid"
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
	mimeTypeHarborVulnerabilityReport = "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
	mimeTypeMicroScannerReport        = "application/vnd.scanner.adapter.vuln.report.raw"

	pathAPIPrefix        = "/api/v1"
	pathMetadata         = "/metadata"
	pathScan             = "/scan"
	pathScanReport       = "/scan/{scanRequestID}/report"
	pathVarScanRequestID = "scanRequestID"

	fieldScanJob       = "scan_job"
	fieldScanRequestID = "scan_request_id"
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

// TODO https://github.com/aquasecurity/harbor-scanner-microscanner/issues/16
func (h *requestHandler) GetMetadata(res http.ResponseWriter, req *http.Request) {
	md := &harbor.ScannerMetadata{
		Name:    "MicroScanner",
		Vendor:  "Aqua Security",
		Version: "3.0.5",
		Capabilities: []*harbor.Capability{
			{
				ArtifactMIMETypes: []string{
					"application/vnd.oci.image.manifest.v1+json",
					"application/vnd.docker.distribution.manifest.v2+json",
				},
				ReportMIMETypes: []string{
					mimeTypeHarborVulnerabilityReport,
					mimeTypeMicroScannerReport,
				},
			},
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

	reqLog := log.WithField(fieldScanRequestID, scanRequest.ID)

	if validationError := h.ValidateScanRequest(scanRequest); validationError != nil {
		reqLog.Errorf("Error while validating scan request: %s", validationError.Message)
		h.SendJSONError(res, *validationError)
		return
	}

	scanJob, err := h.jobQueue.EnqueueScanJob(scanRequest)
	if err != nil {
		reqLog.WithError(err).Error("Error while enqueuing scan job")
		h.SendJSONError(res, harbor.Error{
			HTTPCode: http.StatusInternalServerError,
			Message:  fmt.Sprintf("enqueuing scan job: %s", err.Error()),
		})
		return
	}
	reqLog.WithField(fieldScanJob, scanJob.ID).Debug("Scan job enqueued successfully")

	res.WriteHeader(http.StatusAccepted)
}

func (h *requestHandler) ValidateScanRequest(req harbor.ScanRequest) *harbor.Error {
	if req.ID == "" {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "missing id",
		}
	}

	if req.RegistryURL == "" {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "missing registry_url",
		}
	}

	_, err := url.ParseRequestURI(req.RegistryURL)
	if err != nil {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "invalid registry_url",
		}
	}

	if req.ArtifactRepository == "" {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "missing artifact_repository",
		}
	}

	if req.ArtifactDigest == "" {
		return &harbor.Error{
			HTTPCode: http.StatusUnprocessableEntity,
			Message:  "missing artifact_digest",
		}
	}

	return nil
}

func (h *requestHandler) GetScanReport(res http.ResponseWriter, req *http.Request) {
	log.Debug("Get scan report request received")
	vars := mux.Vars(req)
	scanRequestID, ok := vars[pathVarScanRequestID]
	if !ok {
		http.Error(res, "Bad Request", http.StatusBadRequest)
		return
	}

	scanID, err := uuid.Parse(scanRequestID)
	if err != nil {
		log.WithError(err).WithFields(log.Fields{
			fieldScanRequestID: scanRequestID,
		}).Error("Error while parsing scan request ID")
		h.SendInternalServerError(res)
		return
	}

	scanJob, err := h.jobQueue.GetScanJob(scanID)
	if scanJob == nil {
		log.Errorf("Cannot find scan job for the given scan request ID: %v", scanID)
		http.Error(res, "Not Found", http.StatusNotFound)
		return
	}

	if scanJob.Status == job.Queued || scanJob.Status == job.Pending {
		log.Debugf("Scan job has not finished yet: %v", scanJob)
		res.Header().Set(headerRefreshAfter, "15")
		res.WriteHeader(http.StatusFound)
		return
	}

	if scanJob.Status == job.Failed {
		log.Errorf("Scan job failed for the given scan request ID: %v", scanID)
		h.SendInternalServerError(res)
		return
	}

	if scanJob.Status != job.Finished {
		log.Errorf("Unexpected scan job status: %v", scanJob)
		h.SendInternalServerError(res)
		return
	}

	scanReports, err := h.dataStore.GetScanReports(scanID)
	if scanReports == nil {
		log.Errorf("Cannot find scan reports for the given scan request ID: %v", scanID)
		h.SendInternalServerError(res)
		return
	}

	switch reportMIMEType := h.GetReportMIMEType(req); reportMIMEType {
	case mimeTypeHarborVulnerabilityReport, "":
		res.Header().Set(HeaderContentType, reportMIMEType)
		err = json.NewEncoder(res).Encode(scanReports.HarborVulnerabilityReport)
		if err != nil {
			log.Errorf("Error while marshalling Harbor vulnerability report: %v", err)
			h.SendInternalServerError(res)
		}
		return
	case mimeTypeMicroScannerReport:
		res.Header().Set(HeaderContentType, reportMIMEType)
		err = json.NewEncoder(res).Encode(scanReports.MicroScannerReport)
		if err != nil {
			log.Errorf("Error while marshalling MicroScanner report: %v", err)
			h.SendInternalServerError(res)
		}
		return
	default:
		http.Error(res, "Unrecognized report MIME type", http.StatusUnprocessableEntity)
		return
	}
}

func (h *requestHandler) GetReportMIMEType(req *http.Request) string {
	return strings.TrimSpace(req.Header.Get(headerAccept))
}
