package microscanner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/microscanner"
	log "github.com/sirupsen/logrus"
	"os/exec"
	"strings"
)

const (
	wrapperScript = "microscanner-wrapper.sh"
	fieldImage    = "image"
	fieldExitCode = "exit_code"
	fieldStdErr   = "std_err"
)

// Wrapper wraps the Run method.
//
// Run runs a MicroScanner wrapper script and parses the standard output to ScanReport.
type Wrapper interface {
	Run(image string) (*microscanner.ScanReport, error)
}

type wrapper struct {
	cfg *etc.MicroScannerConfig
}

// NewWrapper constructs Wrapper with the given Config.
func NewWrapper(cfg *etc.MicroScannerConfig) Wrapper {
	return &wrapper{
		cfg: cfg,
	}
}

// Run runs the microscanner-wrapper.sh script to scan the given image and return ScanReport.
func (w *wrapper) Run(image string) (*microscanner.ScanReport, error) {
	if image == "" {
		return nil, errors.New("image must not be blank")
	}

	executable, err := exec.LookPath(wrapperScript)
	if err != nil {
		return nil, fmt.Errorf("searching for %s executable: %v", wrapperScript, err)
	}
	log.WithField(fieldImage, image).Debugf("Wrapper script executable found at %s", executable)

	stderrBuffer := bytes.Buffer{}

	cmd := exec.Command(executable, image)
	cmd.Stderr = &stderrBuffer
	cmd.Env = []string{
		fmt.Sprintf("DOCKER_HOST=%s", w.cfg.DockerHost),
		fmt.Sprintf("MICROSCANNER_TOKEN=%s", w.cfg.Token),
		fmt.Sprintf("MICROSCANNER_OPTIONS=%s", w.cfg.Options),
		fmt.Sprintf("USE_LOCAL=%s", "1"),
	}

	log.WithField(fieldImage, image).Debug("Running wrapper script")

	stdout, err := cmd.Output()
	if err != nil {
		log.WithFields(log.Fields{
			fieldImage:    image,
			fieldExitCode: cmd.ProcessState.ExitCode(),
			fieldStdErr:   stderrBuffer.String(),
		}).Error("Wrapper script failed")
		return nil, fmt.Errorf("running %s: %v", wrapperScript, err)
	}

	log.WithFields(log.Fields{
		fieldImage:    image,
		fieldExitCode: cmd.ProcessState.ExitCode(),
		fieldStdErr:   stderrBuffer.String(),
	}).Debug("Wrapper script finished")

	out := w.extractJSON(stdout)

	var sr microscanner.ScanReport
	err = json.Unmarshal([]byte(out), &sr)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling microscanner scan report: %v", err)
	}
	return &sr, nil
}

func (w *wrapper) extractJSON(stdout []byte) string {
	output := string(stdout)
	start := strings.Index(output, "{\n  \"scan_started\":")
	end := strings.LastIndex(output, "Removing intermediate container")
	return output[start:end]
}
