package microscanner

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/aquasecurity/harbor-microscanner-adapter/pkg/etc"
	"log"
	"os"
	"os/exec"
	"strings"
)

type Wrapper struct {
	cfg *etc.Config
}

// NewWrapper constructs Wrapper with the given Config.
func NewWrapper(cfg *etc.Config) *Wrapper {
	return &Wrapper{
		cfg: cfg,
	}
}

// Scan scans the image by running the microscanner-wrapper script and returns the scan result as string.
func (w *Wrapper) Scan(image string) (string, error) {
	if image == "" {
		return "", errors.New("image must not be nil")
	}

	stdoutBuffer := bytes.Buffer{}

	log.Printf("Started scanning %s ...", image)
	cmd := exec.Command("scan.sh", image)
	cmd.Stderr = os.Stderr
	cmd.Stdout = &stdoutBuffer
	cmd.Env = []string{
		fmt.Sprintf("DOCKER_HOST=%s", w.cfg.DockerHost),
		fmt.Sprintf("MICROSCANNER_TOKEN=%s", w.cfg.MicroScannerToken),
		"USE_LOCAL=1",
	}

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("running scan.sh: %v", err)
	}

	log.Printf("scan.sh exit code %d", cmd.ProcessState.ExitCode())
	log.Printf("Finished scanning %s", image)
	return w.extractJSON(stdoutBuffer), nil
}

func (w *Wrapper) extractJSON(stdoutBuffer bytes.Buffer) string {
	stdoutString := stdoutBuffer.String()
	start := strings.Index(stdoutString, "{\n  \"scan_started\":")
	end := strings.LastIndex(stdoutString, "Removing intermediate container")
	return stdoutString[start:end]
}
