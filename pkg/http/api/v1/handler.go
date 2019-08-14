package v1

import (
	"encoding/json"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/store"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strings"
)

const (
	headerAccept       = "Accept"
	headerContentType  = "Content-Type"
	headerRefreshAfter = "Refresh-After"

	mimeTypeMetadata                  = "application/vnd.scanner.adapter.metadata+json; version=1.0"
	mimeTypeScanRequest               = "application/vnd.scanner.adapter.scan.request+json; version=1.0"
	mimeTypeHarborVulnerabilityReport = "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
	mimeTypeMicroScannerReport        = "application/vnd.scanner.adapter.vuln.report.raw"

	pathAPIPrefix        = "/api/v1"
	pathHealth           = "/health"
	pathMetadata         = "/metadata"
	pathScan             = "/scan"
	pathScanReport       = "/scan/{scanRequestID}/report"
	pathVarScanRequestID = "scanRequestID"
)

type requestHandler struct {
	jobQueue  job.Queue
	dataStore store.DataStore
}

func NewAPIHandler(jobQueue job.Queue, dataStore store.DataStore) http.Handler {
	handler := &requestHandler{
		jobQueue:  jobQueue,
		dataStore: dataStore,
	}

	router := mux.NewRouter()
	v1Router := router.PathPrefix(pathAPIPrefix).Subrouter()

	v1Router.Methods(http.MethodGet).Path(pathHealth).HandlerFunc(handler.GetHealth)
	v1Router.Methods(http.MethodGet).Path(pathMetadata).HandlerFunc(handler.GetMetadata)
	v1Router.Methods(http.MethodPost).Path(pathScan).HandlerFunc(handler.AcceptScanRequest)
	v1Router.Methods(http.MethodGet).Path(pathScanReport).HandlerFunc(handler.GetScanReport)
	return router
}

func (h *requestHandler) GetHealth(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)
}

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

	res.Header().Set(headerContentType, mimeTypeMetadata)
	err := json.NewEncoder(res).Encode(md)
	if err != nil {
		log.Errorf("Error while marshalling metadata response: %v", err)
		h.SendInternalServerError(res)
	}
}

func (h *requestHandler) AcceptScanRequest(res http.ResponseWriter, req *http.Request) {
	scanRequest := harbor.ScanRequest{}
	err := json.NewDecoder(req.Body).Decode(&scanRequest)
	if err != nil {
		log.Errorf("Error while unmarshalling scan request: %v", err)
		http.Error(res, "Bad Request", http.StatusBadRequest)
		return
	}

	scanJob, err := h.jobQueue.EnqueueScanJob(scanRequest)
	if err != nil {
		log.Errorf("Error while enqueuing scan job: %v", err)
		h.SendInternalServerError(res)
		return
	}
	log.Debugf("Enqueued scan job %v for scan request %v", scanJob.ID, scanRequest.ID)

	res.WriteHeader(http.StatusAccepted)
}

func (h *requestHandler) GetScanReport(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	scanRequestID, ok := vars[pathVarScanRequestID]
	if !ok {
		http.Error(res, "Bad Request", http.StatusBadRequest)
		return
	}

	scanID, err := uuid.Parse(scanRequestID)
	if err != nil {
		log.Errorf("Error while parsing scan request ID: %v", scanRequestID)
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
		res.Header().Set(headerContentType, reportMIMEType)
		err = json.NewEncoder(res).Encode(scanReports.HarborVulnerabilityReport)
		if err != nil {
			log.Errorf("Error while marshalling Harbor vulnerability report: %v", err)
			h.SendInternalServerError(res)
		}
		return
	case mimeTypeMicroScannerReport:
		res.Header().Set(headerContentType, reportMIMEType)
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

func (h *requestHandler) SendInternalServerError(res http.ResponseWriter) {
	http.Error(res, "Internal Server Error", http.StatusInternalServerError)
}

func (h *requestHandler) GetReportMIMEType(req *http.Request) string {
	return strings.TrimSpace(req.Header.Get(headerAccept))
}
