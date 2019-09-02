package redis

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/store"
	"github.com/gomodule/redigo/redis"
	"github.com/google/uuid"
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

func (rs *redisStore) SaveScanJob(scanID uuid.UUID, scanJob *job.ScanJob) error {
	conn := rs.cp.Get()
	defer rs.close(conn)

	b, err := json.Marshal(scanJob)
	if err != nil {
		return err
	}

	key := rs.getKeyForScanJob(scanID)
	_, err = conn.Do("SET", key, string(b))
	if err != nil {
		return err
	}
	return nil
}

func (rs *redisStore) GetScanJob(scanID uuid.UUID) (*job.ScanJob, error) {
	conn := rs.cp.Get()
	defer rs.close(conn)

	key := rs.getKeyForScanJob(scanID)
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

func (rs *redisStore) UpdateScanJobStatus(scanID uuid.UUID, currentStatus, newStatus job.ScanJobStatus) error {
	log.WithFields(log.Fields{
		"scan_job":       scanID.String(),
		"current_status": currentStatus.String(),
		"new_status":     newStatus.String(),
	}).Debug("Updating job status")

	scanJob, err := rs.GetScanJob(scanID)
	if err != nil {
		return err
	}
	if scanJob.Status != currentStatus {
		return fmt.Errorf("expected status %v but was %v", currentStatus, scanJob.Status)
	}

	scanJob.Status = newStatus
	return rs.SaveScanJob(scanID, scanJob)
}

func (rs *redisStore) SaveScanReports(scanID uuid.UUID, scanReports *store.ScanReports) error {
	conn := rs.cp.Get()
	defer rs.close(conn)

	b, err := json.Marshal(scanReports)
	if err != nil {
		return err
	}

	key := rs.getKeyForScanReports(scanID)
	_, err = conn.Do("SET", key, string(b))
	return err
}

func (rs *redisStore) GetScanReports(scanID uuid.UUID) (*store.ScanReports, error) {
	conn := rs.cp.Get()
	defer rs.close(conn)

	key := rs.getKeyForScanReports(scanID)
	value, err := redis.String(conn.Do("GET", key))
	if err != nil {
		if err == redis.ErrNil {
			return nil, nil
		}
		return nil, err
	}

	var scanReports store.ScanReports
	err = json.Unmarshal([]byte(value), &scanReports)
	if err != nil {
		return nil, err
	}

	return &scanReports, nil
}

func (rs *redisStore) getKeyForScanJob(scanID uuid.UUID) string {
	return fmt.Sprintf("%s:scan-job:%s", rs.namespace, scanID.String())
}

func (rs *redisStore) getKeyForScanReports(scanID uuid.UUID) string {
	return fmt.Sprintf("%s:scan-reports:%s", rs.namespace, scanID.String())
}

func (rs *redisStore) close(conn redis.Conn) {
	err := conn.Close()
	if err != nil {
		log.Warnf("closing connection: %v", err)
	}
}
