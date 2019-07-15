package etc

import (
	"errors"
	"os"
)

type Config struct {
	Addr              string
	DockerHost        string
	MicroScannerToken string
	RegistryURL       string
}

func GetConfig() (*Config, error) {
	cfg := &Config{
		Addr:       ":8080",
		DockerHost: "tcp://localhost:2375",
	}
	if addr, ok := os.LookupEnv("ADAPTER_ADDR"); ok {
		cfg.Addr = addr
	}
	if dockerHost, ok := os.LookupEnv("ADAPTER_DOCKER_HOST"); ok {
		cfg.DockerHost = dockerHost
	}
	if microScannerToken, ok := os.LookupEnv("ADAPTER_MICRO_SCANNER_TOKEN"); ok {
		cfg.MicroScannerToken = microScannerToken
	} else {
		return nil, errors.New("ADAPTER_MICRO_SCANNER_TOKEN not specified")
	}
	if registryURL, ok := os.LookupEnv("ADAPTER_REGISTRY_URL"); ok {
		cfg.RegistryURL = registryURL
	}
	return cfg, nil
}
