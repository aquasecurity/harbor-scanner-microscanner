package v1

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/scanner"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/store"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strings"
)

const (
	headerAccept      = "Accept"
	headerContentType = "Content-Type"

	mimeTypeMetadata           = "application/vnd.scanner.adapter.metadata+json; version=1.0"
	mimeTypeScanRequest        = "application/vnd.scanner.adapter.scan.request+json; version=1.0"
	mimeTypeHarborVulnReport   = "application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"
	mimeTypeMicroScannerReport = "application/vnd.scanner.adapter.vuln.report.raw"

	pathAPIPrefix        = "/api/v1"
	pathHealth           = "/health"
	pathMetadata         = "/metadata"
	pathScan             = "/scan"
	pathScanReport       = "/scan/{scanRequestID}/report"
	pathVarScanRequestID = "scanRequestID"
)

type requestHandler struct {
	scanner   scanner.Scanner
	jobQueue  job.Queue
	dataStore store.DataStore
}

func NewAPIHandler(scanner scanner.Scanner, jobQueue job.Queue, dataStore store.DataStore) http.Handler {
	handler := &requestHandler{
		scanner:   scanner,
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
	md, err := h.scanner.GetMetadata()
	if err != nil {
		http.Error(res, "Internal Server Error", http.StatusInternalServerError)
	}
	res.Header().Set(headerContentType, mimeTypeMetadata)
	err = json.NewEncoder(res).Encode(md)
	if err != nil {
		http.Error(res, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *requestHandler) AcceptScanRequest(res http.ResponseWriter, req *http.Request) {
	scanRequest := harbor.ScanRequest{}
	err := json.NewDecoder(req.Body).Decode(&scanRequest)
	if err != nil {
		http.Error(res, "Bad Request", http.StatusBadRequest)
		return
	}

	jobID, err := h.jobQueue.EnqueueScanJob(scanRequest)
	if err != nil {
		http.Error(res, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	scanID, err := uuid.Parse(scanRequest.ID)
	if err != nil {
		http.Error(res, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = h.dataStore.SaveScan(scanID, &store.Scan{
		JobID: jobID,
	})
	if err != nil {
		http.Error(res, "Internal Server Error", http.StatusInternalServerError)
		return
	}

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
		http.Error(res, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	scan, err := h.dataStore.GetScan(scanID)
	if scan == nil {
		log.Errorf("Cannot find scan request with the given ID: %v", scanID)
		http.Error(res, "Not Found", http.StatusNotFound)
	}

	reportMIMEType := strings.TrimSpace(req.Header.Get(headerAccept))
	switch reportMIMEType {
	case mimeTypeHarborVulnReport, "":
		scanResult, err := h.scanner.GetHarborVulnerabilityReport(scanRequestID)
		if err != nil {
			http.Error(res, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		res.Header().Set(headerContentType, mimeTypeHarborVulnReport)
		err = json.NewEncoder(res).Encode(scanResult)
		if err != nil {
			http.Error(res, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	case mimeTypeMicroScannerReport:
		scanResult, err := h.scanner.GetMicroScannerReport(scanRequestID)
		if err != nil {
			http.Error(res, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		res.Header().Set(headerContentType, mimeTypeMicroScannerReport)
		err = json.NewEncoder(res).Encode(scanResult)
		if err != nil {
			http.Error(res, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}

	http.Error(res, fmt.Sprintf("unrecognized report type: %s", reportMIMEType), http.StatusUnprocessableEntity)
}
