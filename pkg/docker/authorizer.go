package docker

import (
	"encoding/json"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
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
// Returns the absolute path to a temporary directory where the Docker configuration file is saved.
type Authorizer interface {
	Authorize(req harbor.ScanRequest) (*string, error)
}

type authorizer struct {
}

// NewAuthorizer constructs a new Authorizer.
func NewAuthorizer() Authorizer {
	return &authorizer{}
}

func (a *authorizer) Authorize(req harbor.ScanRequest) (*string, error) {
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
		return nil, fmt.Errorf("creating temporary directory: %v", err)
	}
	dockerConfig, err := os.Create(filepath.Join(tmpDir, "config.json"))
	if err != nil {
		return nil, fmt.Errorf("creating Docker config file: %v", err)
	}
	defer dockerConfig.Close()

	err = config.write(dockerConfig)
	if err != nil {
		return nil, err
	}
	return stringPtr(tmpDir), nil
}

func stringPtr(val string) *string {
	return &val
}
