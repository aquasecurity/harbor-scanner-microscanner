package main

import (
	"github.com/aquasecurity/harbor-microscanner-adapter/pkg/etc"
	"github.com/aquasecurity/harbor-microscanner-adapter/pkg/http/api/v1"
	"github.com/aquasecurity/harbor-microscanner-adapter/pkg/image/microscanner"
	"github.com/gorilla/mux"
	"log"
	"net/http"
)

func main() {
	cfg, err := etc.GetConfig()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	log.Printf("Starting harbor-microscanner-adapter with config %v", cfg)

	scanner, err := microscanner.NewScanner(cfg)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	apiHandler := v1.NewAPIHandler(scanner)

	router := mux.NewRouter()
	v1Router := router.PathPrefix("/api/v1").Subrouter()

	v1Router.Methods("GET").Path("").HandlerFunc(apiHandler.GetVersion)
	v1Router.Methods("POST").Path("/scan").HandlerFunc(apiHandler.CreateScan)
	v1Router.Methods("GET").Path("/scan/{detailsKey}").HandlerFunc(apiHandler.GetScanResult)

	err = http.ListenAndServe(cfg.Addr, router)
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("Error: %v", err)
	}
}
