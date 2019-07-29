package etc

import (
	"errors"
	"os"
)

type Config struct {
	Addr                string
	ScannerDataDir      string
	DockerHost          string
	MicroScannerOptions string
	MicroScannerToken   string
	RegistryURL         string
}

func GetConfig() (*Config, error) {
	cfg := &Config{
		Addr:           ":8080",
		DockerHost:     "tcp://localhost:2375",
		ScannerDataDir: "/data/scanner",
	}
	if addr, ok := os.LookupEnv("SCANNER_ADDR"); ok {
		cfg.Addr = addr
	}
	if dir, ok := os.LookupEnv("SCANNER_DATA_DIR"); ok {
		cfg.ScannerDataDir = dir
	}
	if dockerHost, ok := os.LookupEnv("SCANNER_DOCKER_HOST"); ok {
		cfg.DockerHost = dockerHost
	}
	if microScannerToken, ok := os.LookupEnv("SCANNER_MICROSCANNER_TOKEN"); ok {
		cfg.MicroScannerToken = microScannerToken
	} else {
		return nil, errors.New("SCANNER_MICROSCANNER_TOKEN not specified")
	}
	if registryURL, ok := os.LookupEnv("SCANNER_REGISTRY_URL"); ok {
		cfg.RegistryURL = registryURL
	}
	if options, ok := os.LookupEnv("SCANNER_MICROSCANNER_OPTIONS"); ok {
		cfg.MicroScannerOptions = options
	}
	return cfg, nil
}
