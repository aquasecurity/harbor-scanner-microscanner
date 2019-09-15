package docker

import (
	"encoding/json"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

// RegistryAuth wraps Docker registry access token.
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
		return xerrors.Errorf("marshalling config: %w", err)
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
	tmpDir, err := ioutil.TempDir("", "docker")
	if err != nil {
		return "", xerrors.Errorf("creating temporary directory: %w", err)
	}
	configFileName := filepath.Join(tmpDir, "config.json")
	configFile, err := os.Create(configFileName)
	if err != nil {
		return "", xerrors.Errorf("creating Docker config file: %w", err)
	}
	defer func() {
		if err := configFile.Close(); err != nil {
			log.WithError(err).Warn("Error while closing Docker config file")
		}
	}()

	config := &Config{
		Auths: map[string]RegistryAuth{
			req.Registry.URL: {
				Token: req.Registry.Authorization,
			},
		},
		HTTPHeaders: map[string]string{
			"User-Agent": "Harbor Scanner MicroScanner",
		},
	}

	err = config.write(configFile)
	if err != nil {
		return "", xerrors.Errorf("saving Docker config file: %w", err)
	}
	return configFileName, nil
}
