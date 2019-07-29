package microscanner

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/danielpacak/harbor-scanner-microscanner/pkg/etc"
	"log"
	"os"
	"os/exec"
	"strings"
)

const (
	microscannerWrapperScript = "microscanner-wrapper.sh"
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

	executable, err := exec.LookPath(microscannerWrapperScript)
	if err != nil {
		return "", err
	}

	cmd := exec.Command(executable, image)
	cmd.Stderr = os.Stderr
	cmd.Stdout = &stdoutBuffer
	cmd.Env = []string{
		fmt.Sprintf("DOCKER_HOST=%s", w.cfg.DockerHost),
		fmt.Sprintf("MICROSCANNER_TOKEN=%s", w.cfg.MicroScannerToken),
		fmt.Sprintf("MICROSCANNER_OPTIONS=%s", w.cfg.MicroScannerOptions),
		fmt.Sprintf("USE_LOCAL=%s", "1"),
	}

	err = cmd.Run()
	if err != nil {
		return "", fmt.Errorf("running %s: %v", microscannerWrapperScript, err)
	}

	log.Printf("%s exit code %d", microscannerWrapperScript, cmd.ProcessState.ExitCode())
	log.Printf("Finished scanning %s", image)
	return w.extractJSON(stdoutBuffer), nil
}

func (w *Wrapper) extractJSON(stdoutBuffer bytes.Buffer) string {
	stdoutString := stdoutBuffer.String()
	start := strings.Index(stdoutString, "{\n  \"scan_started\":")
	end := strings.LastIndex(stdoutString, "Removing intermediate container")
	return stdoutString[start:end]
}
