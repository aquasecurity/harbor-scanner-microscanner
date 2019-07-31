package etc

import (
	"errors"
	"os"
)

const (
	StoreDriverFS    = "fs"
	StoreDriverRedis = "redis"
)

type Config struct {
	Addr         string
	DockerHost   string
	RegistryURL  string
	StoreDriver  string
	FSStore      *FSStoreConfig
	RedisStore   *RedisStoreConfig
	MicroScanner *MicroScannerConfig
}

type FSStoreConfig struct {
	DataDir string
}

type RedisStoreConfig struct {
	RedisURL string
}

type MicroScannerConfig struct {
	Token   string
	Options string
}

func GetConfig() (*Config, error) {
	cfg := &Config{
		Addr:        ":8080",
		DockerHost:  "tcp://localhost:2375",
		StoreDriver: StoreDriverRedis,
		RedisStore: &RedisStoreConfig{
			RedisURL: "redis://localhost:6379",
		},
		FSStore: &FSStoreConfig{
			DataDir: "/data/scanner",
		},
		MicroScanner: &MicroScannerConfig{},
	}

	if addr, ok := os.LookupEnv("SCANNER_ADDR"); ok {
		cfg.Addr = addr
	}

	if dockerHost, ok := os.LookupEnv("SCANNER_DOCKER_HOST"); ok {
		cfg.DockerHost = dockerHost
	}

	if registryURL, ok := os.LookupEnv("SCANNER_REGISTRY_URL"); ok {
		cfg.RegistryURL = registryURL
	}

	if driver, ok := os.LookupEnv("SCANNER_STORE_DRIVER"); ok {
		cfg.StoreDriver = driver
	}

	if microScannerToken, ok := os.LookupEnv("SCANNER_MICROSCANNER_TOKEN"); ok {
		cfg.MicroScanner.Token = microScannerToken
	} else {
		return nil, errors.New("SCANNER_MICROSCANNER_TOKEN not specified")
	}

	if options, ok := os.LookupEnv("SCANNER_MICROSCANNER_OPTIONS"); ok {
		cfg.MicroScanner.Options = options
	}

	if dir, ok := os.LookupEnv("SCANNER_STORE_FS_DATA_DIR"); ok {
		cfg.FSStore.DataDir = dir
	}

	return cfg, nil
}
