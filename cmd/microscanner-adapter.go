package main

import (
	"github.com/aquasecurity/microscanner-proxy/pkg/http/api/v1"
	"github.com/aquasecurity/microscanner-proxy/pkg/image/dummy"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"os"
)

type config struct {
	addr     string
	dataFile string
}

func main() {
	cfg := getConfig()
	log.Printf("Starting harbor-microscanner-adapter with config %v", cfg)

	scanner, err := dummy.NewScanner(cfg.dataFile)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	apiHandler := v1.NewAPIHandler(scanner)

	router := mux.NewRouter()
	v1Router := router.PathPrefix("/api/v1").Subrouter()

	v1Router.Methods("POST").Path("/scan").HandlerFunc(apiHandler.CreateScan)
	v1Router.Methods("GET").Path("/scan/{digest}").HandlerFunc(apiHandler.GetScanResult)

	err = http.ListenAndServe(cfg.addr, router)
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("Error: %v", err)
	}
}

func getConfig() config {
	cfg := config{
		addr:     ":8080",
		dataFile: "/app/data/dummy-scanner.json",
	}
	if addr, ok := os.LookupEnv("MICROSCANNER_ADDR"); ok {
		cfg.addr = addr
	}
	if dataFile, ok := os.LookupEnv("MICROSCANNER_DATA_FILE"); ok {
		cfg.dataFile = dataFile
	}
	return cfg
}
