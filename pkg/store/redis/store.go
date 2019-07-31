package redis

import (
	"encoding/json"
	"errors"
	"github.com/danielpacak/harbor-scanner-contract/pkg/model/harbor"
	"github.com/danielpacak/harbor-scanner-microscanner/pkg/store"
	"github.com/gomodule/redigo/redis"
	"github.com/google/uuid"
	"log"
)

// https://itnext.io/storing-go-structs-in-redis-using-rejson-dab7f8fc0053
// TODO Use connection pool and other connection params
// TODO Consider using ReJSON
type redisStore struct {
	redisURL string
}

type dataBlock struct {
	ScanResult string
	CreatedAt  string
}

func NewStore(redisURL string) (store.DataStore, error) {
	if redisURL == "" {
		return nil, errors.New("redisURL must not be nil")
	}
	return &redisStore{redisURL: redisURL}, nil
}

func (rs *redisStore) Save(scanID uuid.UUID, hsr *harbor.ScanResult) error {
	conn, err := redis.DialURL(rs.redisURL)
	if err != nil {
		return err
	}
	defer conn.Close()

	b, err := json.Marshal(hsr)
	if err != nil {
		return err
	}

	block := dataBlock{
		ScanResult: string(b),
		CreatedAt:  "10:30", // set it
	}

	reply, err := conn.Do("HMSET", redis.Args{scanID.String()}.AddFlat(block)...)
	if err != nil {
		return err
	}
	log.Printf("reply: %v", reply)
	return nil
}

func (rs *redisStore) Get(scanID uuid.UUID) (*harbor.ScanResult, error) {
	conn, err := redis.DialURL(rs.redisURL)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	value, err := redis.Values(conn.Do("HGETALL", scanID.String()))
	if err != nil {
		return nil, err
	}
	block := dataBlock{}
	err = redis.ScanStruct(value, &block)
	if err != nil {
		return nil, err
	}

	hsr := &harbor.ScanResult{}
	err = json.Unmarshal([]byte(block.ScanResult), hsr)
	if err != nil {
		return nil, err
	}

	return hsr, nil
}
