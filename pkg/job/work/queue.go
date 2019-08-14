package work

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/microscanner"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/store"
	"github.com/gocraft/work"
	"github.com/gomodule/redigo/redis"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

const (
	jobScanImage   = "scan_image"
	scannerArg     = "scanner"
	scanRequestArg = "scan_request"
)

type workQueue struct {
	redisPool  *redis.Pool
	workerPool *work.WorkerPool
	enqueuer   *work.Enqueuer
	dataStore  store.DataStore
}

func NewWorkQueue(cfg *etc.JobQueueConfig, scanner microscanner.Scanner, dataStore store.DataStore) (job.Queue, error) {
	redisPool := &redis.Pool{
		MaxActive: cfg.Pool.MaxActive,
		MaxIdle:   cfg.Pool.MaxIdle,
		Wait:      true,
		Dial: func() (redis.Conn, error) {
			return redis.DialURL(cfg.RedisURL)
		},
	}

	workerPool := work.NewWorkerPool(workQueue{}, cfg.WorkerConcurrency, cfg.Namespace, redisPool)
	enqueuer := work.NewEnqueuer(cfg.Namespace, redisPool)

	workerPool.Middleware(func(j *work.Job, n work.NextMiddlewareFunc) error {
		// TODO Is there any better way to inject dependencies?
		j.Args[scannerArg] = scanner
		return n()
	})

	workerPool.JobWithOptions(jobScanImage, work.JobOptions{Priority: 1, MaxFails: 1}, (*workQueue).ScanImage)

	return &workQueue{
		redisPool:  redisPool,
		workerPool: workerPool,
		enqueuer:   enqueuer,
		dataStore:  dataStore,
	}, nil
}

func (wq *workQueue) Start() {
	wq.workerPool.Start()
}

func (wq *workQueue) Stop() {
	wq.workerPool.Stop()
}

func (wq *workQueue) EnqueueScanJob(sr harbor.ScanRequest) (*job.ScanJob, error) {
	log.Debugf("Enqueueing scan job for scan request ID %v", sr.ID)

	b, err := json.Marshal(sr)
	if err != nil {
		return nil, fmt.Errorf("marshalling scan request: %v", err)
	}

	j, err := wq.enqueuer.Enqueue(jobScanImage, work.Q{
		scanRequestArg: string(b),
	})
	if err != nil {
		return nil, fmt.Errorf("enqueuing scan image job: %v", err)
	}
	log.Debugf("Successfully enqueued scan job with ID %v for scan request ID %v", j.ID, sr.ID)

	scanID, err := uuid.Parse(sr.ID)
	if err != nil {
		return nil, fmt.Errorf("parsing scan request ID: %v", err)
	}

	scanJob := &job.ScanJob{
		ID:     j.ID,
		Status: job.Queued,
	}

	err = wq.dataStore.SaveScanJob(scanID, scanJob)
	if err != nil {
		return nil, fmt.Errorf("saving scan job %v", err)
	}

	return scanJob, nil
}

func (wq *workQueue) GetScanJob(scanID uuid.UUID) (*job.ScanJob, error) {
	return wq.dataStore.GetScanJob(scanID)
}

func (wq *workQueue) ScanImage(job *work.Job) error {
	log.Debugf("Scan job started: %v", job.ID)
	sc, ok := job.Args[scannerArg].(microscanner.Scanner)
	if !ok {
		return fmt.Errorf("getting scanner from job args")
	}

	var sr harbor.ScanRequest
	b := []byte(job.ArgString(scanRequestArg))
	err := json.Unmarshal(b, &sr)
	if err != nil {
		return fmt.Errorf("unmarshalling scan request: %v", err)
	}

	if err := job.ArgError(); err != nil {
		return err
	}

	err = sc.Scan(sr)
	if err != nil {
		return err
	}
	log.Debugf("Scan job finished: %s", job.ID)
	return err
}
