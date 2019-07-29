package v1

import (
	"encoding/json"
	"github.com/danielpacak/harbor-scanner-contract/pkg/image"
	"github.com/danielpacak/harbor-scanner-contract/pkg/model/harbor"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

type APIHandler struct {
	scanner image.Scanner
}

func NewAPIHandler(scanner image.Scanner) *APIHandler {
	return &APIHandler{
		scanner: scanner,
	}
}

func (h *APIHandler) GetVersion(res http.ResponseWriter, req *http.Request) {
	res.WriteHeader(http.StatusOK)
}

func (h *APIHandler) CreateScan(res http.ResponseWriter, req *http.Request) {
	err := h.DoCreateScan(res, req)
	if err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(res, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *APIHandler) DoCreateScan(res http.ResponseWriter, req *http.Request) error {
	scanRequest := harbor.ScanRequest{}
	err := json.NewDecoder(req.Body).Decode(&scanRequest)
	if err != nil {
		return err
	}

	scanResponse, err := h.scanner.Scan(scanRequest)
	if err != nil {
		return err
	}

	res.WriteHeader(http.StatusCreated)

	res.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(res).Encode(scanResponse)
	if err != nil {
		return err
	}
	return nil
}

func (h *APIHandler) GetScanResult(res http.ResponseWriter, req *http.Request) {
	err := h.DoGetScanResult(res, req)
	if err != nil {
		log.Printf("ERROR: %v", err)
		http.Error(res, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (h *APIHandler) DoGetScanResult(res http.ResponseWriter, req *http.Request) error {
	vars := mux.Vars(req)
	detailsKey, _ := vars["detailsKey"]

	scanResult, err := h.scanner.GetResult(detailsKey)
	if err != nil {
		return err
	}

	res.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(res).Encode(scanResult)
	if err != nil {
		return err
	}
	return nil
}
