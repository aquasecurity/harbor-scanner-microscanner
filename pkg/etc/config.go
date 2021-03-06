package etc

import (
	"errors"
	"os"
)

const (
	defaultRedisURL = "redis://localhost:6379"
)

type Config struct {
	APIAddr      string
	RegistryURL  string
	MicroScanner *MicroScannerConfig
	RedisStore   *RedisStoreConfig
	JobQueue     *JobQueueConfig
}

type RedisStoreConfig struct {
	RedisURL  string
	Namespace string
	Pool      *PoolConfig
}

type MicroScannerConfig struct {
	DockerHost string
	Token      string
	Options    string
}

type JobQueueConfig struct {
	RedisURL          string
	Namespace         string
	WorkerConcurrency uint
	Pool              *PoolConfig
}

type PoolConfig struct {
	MaxActive int
	MaxIdle   int
}

func GetConfig() (*Config, error) {
	cfg := &Config{
		APIAddr: ":8080",
		MicroScanner: &MicroScannerConfig{
			DockerHost: "tcp://localhost:2375",
			Options:    "--continue-on-failure --full-output",
		},
		RedisStore: &RedisStoreConfig{
			RedisURL:  defaultRedisURL,
			Namespace: "harbor.scanner.microscanner:store",
			Pool: &PoolConfig{
				MaxActive: 5,
				MaxIdle:   5,
			},
		},
		JobQueue: &JobQueueConfig{
			RedisURL:          defaultRedisURL,
			Namespace:         "harbor.scanner.microscanner:job-queue",
			WorkerConcurrency: 1,
			Pool: &PoolConfig{
				MaxActive: 5,
				MaxIdle:   5,
			},
		},
	}

	if addr, ok := os.LookupEnv("SCANNER_API_ADDR"); ok {
		cfg.APIAddr = addr
	}

	if dockerHost, ok := os.LookupEnv("SCANNER_DOCKER_HOST"); ok {
		cfg.MicroScanner.DockerHost = dockerHost
	}

	if registryURL, ok := os.LookupEnv("SCANNER_REGISTRY_URL"); ok {
		cfg.RegistryURL = registryURL
	}

	if microScannerToken, ok := os.LookupEnv("SCANNER_MICROSCANNER_TOKEN"); ok {
		cfg.MicroScanner.Token = microScannerToken
	} else {
		return nil, errors.New("env SCANNER_MICROSCANNER_TOKEN not set")
	}

	if options, ok := os.LookupEnv("SCANNER_MICROSCANNER_OPTIONS"); ok {
		cfg.MicroScanner.Options = options
	}

	if redisURL, ok := os.LookupEnv("SCANNER_STORE_REDIS_URL"); ok {
		cfg.RedisStore.RedisURL = redisURL
	}

	if ns, ok := os.LookupEnv("SCANNER_STORE_REDIS_NAMESPACE"); ok {
		cfg.RedisStore.Namespace = ns
	}

	if redisURL, ok := os.LookupEnv("SCANNER_JOB_QUEUE_REDIS_URL"); ok {
		cfg.JobQueue.RedisURL = redisURL
	}

	if ns, ok := os.LookupEnv("SCANNER_JOB_QUEUE_REDIS_NAMESPACE"); ok {
		cfg.JobQueue.Namespace = ns
	}

	return cfg, nil
}
