package work

import (
	"encoding/json"
	"fmt"
	"github.com/danielpacak/harbor-scanner-microscanner/pkg/etc"
	"github.com/danielpacak/harbor-scanner-microscanner/pkg/job"
	"github.com/danielpacak/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/danielpacak/harbor-scanner-microscanner/pkg/scanner"
	"github.com/gocraft/work"
	"github.com/gomodule/redigo/redis"
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
}

func NewWorkQueue(cfg *etc.Config, scanner scanner.Scanner) (job.Queue, error) {
	redisPool := &redis.Pool{
		MaxActive: cfg.JobQueue.Pool.MaxActive,
		MaxIdle:   cfg.JobQueue.Pool.MaxIdle,
		Wait:      true,
		Dial: func() (redis.Conn, error) {
			return redis.DialURL(cfg.JobQueue.RedisURL)
		},
	}

	workerPool := work.NewWorkerPool(workQueue{}, cfg.JobQueue.WorkerConcurrency, cfg.JobQueue.Namespace, redisPool)
	enqueuer := work.NewEnqueuer(cfg.JobQueue.Namespace, redisPool)

	workerPool.Middleware(func(j *work.Job, n work.NextMiddlewareFunc) error {
		// TODO Is there any better way to do that?
		log.Debugf("Setting scanner as job arg: %s", scannerArg)
		j.Args[scannerArg] = scanner
		return n()
	})

	workerPool.JobWithOptions(jobScanImage, work.JobOptions{Priority: 1, MaxFails: 1}, (*workQueue).ScanImage)

	return &workQueue{
		redisPool:  redisPool,
		workerPool: workerPool,
		enqueuer:   enqueuer,
	}, nil
}

func (wq *workQueue) Start() {
	wq.workerPool.Start()
}

func (wq *workQueue) Stop() {
	wq.workerPool.Stop()
}

func (wq *workQueue) SubmitScanImageJob(sr harbor.ScanRequest) (string, error) {
	log.Debugf("Submitting scan image job %v", sr)

	b, err := json.Marshal(sr)
	if err != nil {
		return "", fmt.Errorf("marshalling scan request: %v", err)
	}

	j, err := wq.enqueuer.Enqueue(jobScanImage, work.Q{
		scanRequestArg: string(b),
	})
	if err != nil {
		return "", fmt.Errorf("enqueuing scan image job: %v", err)
	}
	log.Debugf("Successfully enqueued job: %v", j.ID)
	return j.ID, nil
}

func (wq *workQueue) ScanImage(job *work.Job) error {
	log.Debugf("Scan job started: %v", job.ID)
	log.Debugf("Getting scanner from job arg: %s", scannerArg)
	sc, ok := job.Args[scannerArg].(scanner.Scanner)
	if !ok {
		return fmt.Errorf("getting scanner from job arg")
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

	err = sc.SubmitScan(sr)
	if err != nil {
		return err
	}
	log.Debugf("Scan job finished: %s", job.ID)
	return err
}
