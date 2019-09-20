package redis

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/store"
	"github.com/gomodule/redigo/redis"
	log "github.com/sirupsen/logrus"
)

type redisStore struct {
	namespace string
	cp        *redis.Pool
}

func NewDataStore(cfg *etc.RedisStoreConfig) (store.DataStore, error) {
	if cfg == nil {
		return nil, errors.New("cfg must not be nil")
	}
	return &redisStore{
		namespace: cfg.Namespace,
		cp: &redis.Pool{
			MaxActive: cfg.Pool.MaxActive,
			MaxIdle:   cfg.Pool.MaxIdle,
			Wait:      true,
			Dial: func() (redis.Conn, error) {
				return redis.DialURL(cfg.RedisURL)
			},
		},
	}, nil
}

func (rs *redisStore) SaveScanJob(scanJob *job.ScanJob) error {
	if scanJob.ID == "" {
		return errors.New("ID must not be blank")
	}

	conn := rs.cp.Get()
	defer rs.close(conn)

	b, err := json.Marshal(scanJob)
	if err != nil {
		return err
	}

	key := rs.getKeyForScanJob(scanJob.ID)
	_, err = conn.Do("SET", key, string(b))
	if err != nil {
		return err
	}
	return nil
}

func (rs *redisStore) GetScanJob(scanJobID string) (*job.ScanJob, error) {
	conn := rs.cp.Get()
	defer rs.close(conn)

	key := rs.getKeyForScanJob(scanJobID)
	value, err := redis.String(conn.Do("GET", key))
	if err != nil {
		if err == redis.ErrNil {
			return nil, nil
		}
		return nil, err
	}

	var scanJob job.ScanJob
	err = json.Unmarshal([]byte(value), &scanJob)
	if err != nil {
		return nil, err
	}

	return &scanJob, nil
}

func (rs *redisStore) UpdateStatus(scanJobID string, newStatus job.ScanJobStatus, error ...string) error {
	log.WithFields(log.Fields{
		"scan_job_id": scanJobID,
		"new_status":  newStatus.String(),
	}).Debug("Updating status for scan job")

	scanJob, err := rs.GetScanJob(scanJobID)
	if err != nil {
		return err
	}

	scanJob.Status = newStatus
	if error != nil && len(error) > 0 {
		scanJob.Error = error[0]
	}

	return rs.SaveScanJob(scanJob)
}

func (rs *redisStore) UpdateReports(scanJobID string, reports job.ScanReports) error {
	log.WithFields(log.Fields{
		"scan_job_id": scanJobID,
	}).Debug("Updating reports for scan job")

	scanJob, err := rs.GetScanJob(scanJobID)
	if err != nil {
		return err
	}

	scanJob.Reports = &reports
	return rs.SaveScanJob(scanJob)
}

func (rs *redisStore) getKeyForScanJob(scanID string) string {
	return fmt.Sprintf("%s:scan-job:%s", rs.namespace, scanID)
}

func (rs *redisStore) close(conn redis.Conn) {
	err := conn.Close()
	if err != nil {
		log.Warnf("closing connection: %v", err)
	}
}
