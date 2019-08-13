package redis

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/store"
	"github.com/gomodule/redigo/redis"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
)

type redisStore struct {
	namespace string
	cp        *redis.Pool
}

func NewStore(cfg *etc.RedisStoreConfig) (store.DataStore, error) {
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

func (rs *redisStore) SaveScan(scanID uuid.UUID, scan *store.Scan) error {
	conn := rs.cp.Get()
	defer rs.close(conn)

	b, err := json.Marshal(scan)
	if err != nil {
		return err
	}

	key := rs.getKeyForScan(scanID)
	reply, err := conn.Do("SET", key, string(b))
	if err != nil {
		return err
	}
	log.Debugf("Redis command reply: %v", reply)

	return nil
}

func (rs *redisStore) GetScan(scanID uuid.UUID) (*store.Scan, error) {
	conn := rs.cp.Get()
	defer rs.close(conn)

	key := rs.getKeyForScan(scanID)
	value, err := redis.String(conn.Do("GET", key))
	if err != nil {
		if err == redis.ErrNil {
			return nil, nil
		}
		return nil, err
	}

	var scan store.Scan
	err = json.Unmarshal([]byte(value), &scan)
	if err != nil {
		return nil, err
	}

	return &scan, nil
}

func (rs *redisStore) getKeyForScan(scanID uuid.UUID) string {
	return fmt.Sprintf("%s:scan:%s", rs.namespace, scanID.String())
}

func (rs *redisStore) close(conn redis.Conn) {
	err := conn.Close()
	if err != nil {
		log.Warnf("closing connection: %v", err)
	}
}
