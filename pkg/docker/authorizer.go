package docker

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	log "github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

type RegistryAuth struct {
	Token string `json:"registrytoken"`
}

// Config represents Docker configuration file, typically stored in `$HOME/.docker/config.json`.
type Config struct {
	Auths       map[string]RegistryAuth `json:"auths"`
	HTTPHeaders map[string]string       `json:"HttpHeaders"`
}

// Write writes Docker config to the given output.
func (c *Config) write(out io.Writer) error {
	bytes, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("marshalling config: %v", err)
	}
	_, err = out.Write(bytes)
	return err
}

// Authorizer wraps the Authorize method.
//
// Authorize creates Docker configuration and writes it to the `config.json` file in a temporary directory.
// Returns the absolute path to the configuration file.
type Authorizer interface {
	Authorize(req harbor.ScanRequest) (string, error)
}

type authorizer struct {
}

// NewAuthorizer constructs a new Authorizer.
func NewAuthorizer() Authorizer {
	return &authorizer{}
}

func (a *authorizer) Authorize(req harbor.ScanRequest) (string, error) {
	config := &Config{
		Auths: map[string]RegistryAuth{
			req.RegistryURL: {
				Token: req.RegistryAuthorization,
			},
		},
		HTTPHeaders: map[string]string{
			"User-Agent": "Harbor Scanner Microscanner",
		},
	}
	tmpDir, err := ioutil.TempDir("", "docker")
	if err != nil {
		return "", fmt.Errorf("creating temporary directory: %v", err)
	}
	configFileName := filepath.Join(tmpDir, "config.json")
	configFile, err := os.Create(configFileName)
	if err != nil {
		return "", fmt.Errorf("creating Docker config file: %v", err)
	}
	defer func() {
		if err := configFile.Close(); err != nil {
			log.Warnf("Error while closing Docker config file: %v", err)
		}
	}()

	err = config.write(configFile)
	if err != nil {
		return "", err
	}
	return configFileName, nil
}
