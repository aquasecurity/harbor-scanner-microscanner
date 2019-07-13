package main

import (
	"github.com/aquasecurity/harbor-microscanner-adapter/pkg/http/api/v1"
	"github.com/aquasecurity/harbor-microscanner-adapter/pkg/image/microscanner"
	"github.com/gorilla/mux"
	"log"
	"net/http"
	"os"
)

type config struct {
	addr       string
	dataFile   string
	dockerHost string
}

func main() {
	cfg := getConfig()
	log.Printf("Starting harbor-microscanner-adapter with config %v", cfg)

	scanner, err := microscanner.NewScanner(cfg.dataFile)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	apiHandler := v1.NewAPIHandler(scanner)

	router := mux.NewRouter()
	v1Router := router.PathPrefix("/api/v1").Subrouter()

	v1Router.Methods("POST").Path("/scan").HandlerFunc(apiHandler.CreateScan)
	v1Router.Methods("GET").Path("/scan/{detailsKey}").HandlerFunc(apiHandler.GetScanResult)

	err = http.ListenAndServe(cfg.addr, router)
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("Error: %v", err)
	}
}

func getConfig() config {
	cfg := config{
		addr:     ":8080",
		dataFile: "/app/data/dummy-scanner.json",
		dockerHost: "tcp://localhost:2375",
	}
	if addr, ok := os.LookupEnv("ADAPTER_ADDR"); ok {
		cfg.addr = addr
	}
	if dataFile, ok := os.LookupEnv("ADAPTER_DATA_FILE"); ok {
		cfg.dataFile = dataFile
	}
	if dockerHost, ok := os.LookupEnv("ADAPTER_DOCKER_HOST"); ok{
		cfg.dockerHost = dockerHost
	}
	return cfg
}
