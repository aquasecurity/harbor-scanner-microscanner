package main

import (
	"fmt"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/http/api/v1"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job/work"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/scanner/microscanner"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/store"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/store/redis"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
)

func init() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	log.SetReportCaller(false)
}

func main() {
	cfg, err := etc.GetConfig()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	log.Infof("Starting harbor-scanner-microscanner with config %v", cfg)

	dataStore, err := GetStore(cfg)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	scanner, err := microscanner.NewScanner(cfg, model.NewTransformer(), dataStore)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	jobQueue, err := work.NewWorkQueue(cfg, scanner)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	jobQueue.Start()

	apiHandler := v1.NewAPIHandler(scanner, jobQueue)

	router := mux.NewRouter()
	v1Router := router.PathPrefix("/api/v1").Subrouter()

	v1Router.Methods(http.MethodGet).Path("").HandlerFunc(apiHandler.GetVersion)
	v1Router.Methods(http.MethodGet).Path("/metadata").HandlerFunc(apiHandler.GetMetadata)
	v1Router.Methods(http.MethodPost).Path("/scan").HandlerFunc(apiHandler.SubmitScan)
	v1Router.Methods(http.MethodGet).Path("/scan/{scanRequestID}/report").HandlerFunc(apiHandler.GetScanReport)

	err = http.ListenAndServe(cfg.APIAddr, router)
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("Error: %v", err)
	}
}

func GetStore(cfg *etc.Config) (store.DataStore, error) {
	switch cfg.StoreDriver {
	case etc.StoreDriverRedis:
		return redis.NewStore(cfg.RedisStore)
	default:
		return nil, fmt.Errorf("unrecognized store type: %s", cfg.StoreDriver)
	}
}
