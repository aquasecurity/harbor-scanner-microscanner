package v1

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/scanner"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strings"
)

const (
	headerContentType          = "Content-Type"
	mimeApplicationJSON        = "application/json"
	mimeTypeHarborScanReport   = "application/vnd.scanner.adapter.vuln.report.harbor.v1+json"
	mimeTypeMicroScannerReport = "application/vnd.scanner.adapter.vuln.report.raw"
)

type APIHandler struct {
	scanner  scanner.Scanner
	jobQueue job.Queue
}

func NewAPIHandler(scanner scanner.Scanner, jobQueue job.Queue) *APIHandler {
	return &APIHandler{
		scanner:  scanner,
		jobQueue: jobQueue,
	}
}

func (h *APIHandler) GetVersion(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)
}

func (h *APIHandler) GetMetadata(res http.ResponseWriter, req *http.Request) {
	md, err := h.scanner.GetMetadata()
	if err != nil {
		http.Error(res, "Internal Server Error", http.StatusInternalServerError)
	}
	res.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(res).Encode(md)
	if err != nil {
		http.Error(res, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *APIHandler) SubmitScan(res http.ResponseWriter, req *http.Request) {
	err := h.doCreateScan(res, req)
	if err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(res, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *APIHandler) doCreateScan(res http.ResponseWriter, req *http.Request) error {
	scanRequest := harbor.ScanRequest{}
	err := json.NewDecoder(req.Body).Decode(&scanRequest)
	if err != nil {
		return fmt.Errorf("unmarshalling scan request: %v", err)
	}

	if _, err = h.jobQueue.SubmitScanImageJob(scanRequest); err != nil {
		return fmt.Errorf("submitting scan job: %v", err)
	}

	res.WriteHeader(http.StatusAccepted)
	return nil
}

func (h *APIHandler) GetScanReport(res http.ResponseWriter, req *http.Request) {
	err := h.doGetScanResult(res, req)
	if err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(res, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *APIHandler) doGetScanResult(res http.ResponseWriter, req *http.Request) error {
	vars := mux.Vars(req)
	scanRequestID, ok := vars["scanRequestID"]
	if !ok {
		return errors.New("scanRequestID must not be nil")
	}

	reportMIMEType := strings.TrimSpace(req.Header.Get("Accept"))
	switch reportMIMEType {
	case mimeTypeHarborScanReport:
		scanResult, err := h.scanner.GetScanReportHarbor(scanRequestID)
		if err != nil {
			return err
		}

		res.Header().Set(headerContentType, mimeTypeHarborScanReport)
		err = json.NewEncoder(res).Encode(scanResult)
		if err != nil {
			return err
		}

	case mimeTypeMicroScannerReport:
		scanResult, err := h.scanner.GetScanReportRaw(scanRequestID)
		if err != nil {
			return err
		}
		res.Header().Set(headerContentType, mimeTypeMicroScannerReport)
		res.Header().Set(headerContentType, mimeApplicationJSON)
		err = json.NewEncoder(res).Encode(scanResult)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unrecognized report type: %s", reportMIMEType)
	}

	return nil
}
