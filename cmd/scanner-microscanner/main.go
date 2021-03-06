package main

import (
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/docker"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/http/api/v1"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job/work"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/microscanner"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/store/redis"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
)

func init() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	log.SetReportCaller(false)
	log.SetFormatter(&log.JSONFormatter{})
}

func main() {
	cfg, err := etc.GetConfig()
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	log.Info("Starting harbor-scanner-microscanner")

	authorizer := docker.NewAuthorizer()
	wrapper := microscanner.NewWrapper(cfg.MicroScanner)
	transformer := model.NewTransformer()

	dataStore, err := redis.NewDataStore(cfg.RedisStore)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	scanner := microscanner.NewScanner(authorizer, wrapper, transformer, dataStore)

	jobQueue, err := work.NewJobQueue(cfg.JobQueue, scanner, dataStore)
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
