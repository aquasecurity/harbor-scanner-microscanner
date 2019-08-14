package main

import (
	"fmt"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/http/api/v1"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job/work"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/microscanner"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/store"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/store/redis"
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

	wrapper := microscanner.NewWrapper(cfg.MicroScanner)
	transformer := model.NewTransformer()

	dataStore, err := GetDataStore(cfg)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	scanner, err := microscanner.NewScanner(wrapper, transformer, dataStore)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	jobQueue, err := work.NewWorkQueue(cfg.JobQueue, scanner, dataStore)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}
	jobQueue.Start()

	apiHandler := v1.NewAPIHandler(jobQueue, dataStore)

	err = http.ListenAndServe(cfg.APIAddr, apiHandler)
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("Error: %v", err)
	}
}

func GetDataStore(cfg *etc.Config) (store.DataStore, error) {
	switch cfg.StoreDriver {
	case etc.StoreDriverRedis:
		return redis.NewStore(cfg.RedisStore)
	default:
		return nil, fmt.Errorf("unrecognized store type: %s", cfg.StoreDriver)
	}
}
