package v1

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/microscanner-proxy/pkg/image"
	"github.com/aquasecurity/microscanner-proxy/pkg/model"
	"github.com/gorilla/mux"
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

func (h *APIHandler) CreateScan(res http.ResponseWriter, req *http.Request) {
	scanRequest := model.ScanRequest{}
	err := json.NewDecoder(req.Body).Decode(&scanRequest)
	if err != nil {
		http.Error(res, "Internal Server Error", 500)
		return
	}

	fmt.Printf("Request received to scan image=[%v]\n", scanRequest)

	err = h.scanner.Scan(scanRequest)
	if err != nil {
		http.Error(res, "Internal Server Error", 500)
		return
	}

	res.WriteHeader(http.StatusCreated)
}

func (h *APIHandler) GetScan(res http.ResponseWriter, req *http.Request) {
	vars := mux.Vars(req)
	correlationID, _ := vars["correlationID"]
	fmt.Printf("Request received for scan results with correlationID=[%v])\n", correlationID)

	scanResults, err := h.scanner.GetResults(correlationID)
	if err != nil {
		http.Error(res, "Internal Server Error", 500)
		return
	}

	res.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(res).Encode(scanResults)
	if err != nil {
		http.Error(res, "Internal Server Error", 500)
		return
	}
}
