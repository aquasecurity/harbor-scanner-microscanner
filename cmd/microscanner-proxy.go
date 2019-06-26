package main

import (
	"fmt"
	"github.com/aquasecurity/microscanner-proxy/pkg/http/api/v1"
	"github.com/aquasecurity/microscanner-proxy/pkg/image/dummy"
	"github.com/gorilla/mux"
	"net/http"
	"os"
)

type config struct {
	addr     string
	dataFile string
	token    string
}

func main() {
	cfg := getConfig()
	fmt.Printf("Starting microscanner proxy with config %v\n", cfg)

	scanner, err := dummy.NewScanner(cfg.dataFile)
	if err != nil {
		fmt.Printf("Error: %v", err)
		os.Exit(1)
	}

	apiHandler := v1.NewAPIHandler(scanner)

	router := mux.NewRouter()
	v1Router := router.PathPrefix("/api/v1").Subrouter()

	v1Router.Methods("POST").Path("/scan").HandlerFunc(apiHandler.CreateScan)
	v1Router.Methods("GET").Path("/scan/{correlationID}").HandlerFunc(apiHandler.GetScan)

	err = http.ListenAndServe(cfg.addr, router)
	if err != nil && err != http.ErrServerClosed {
		fmt.Printf("Error: %v", err)
		os.Exit(1)
	}
}

func getConfig() config {
	cfg := config{
		addr:     ":8080",
		dataFile: "/app/data/dummy-scanner.json",
	}
	if addr, ok := os.LookupEnv("MICRO_SCANNER_ADDR"); ok {
		cfg.addr = addr
	}
	if dataFile, ok := os.LookupEnv("MICRO_SCANNER_DATA_FILE"); ok {
		cfg.dataFile = dataFile
	}
	if token, ok := os.LookupEnv("MICRO_SCANNER_TOKEN"); ok {
		cfg.token = token
	}
	return cfg
}
