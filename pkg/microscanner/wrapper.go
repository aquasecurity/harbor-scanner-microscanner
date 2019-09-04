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
	"path/filepath"
	"strings"
)

const (
	wrapperScript = "microscanner-wrapper.sh"

	fieldImage        = "image"
	fieldDockerConfig = "docker_config"
	fieldExitCode     = "exit_code"
	fieldStdErr       = "std_err"

	overridingErrorCodeMessage = "\u001b[91mOverriding non-zero error code due to --continue-on-failure setting\n\u001b[0m"
	stdoutJSONStartMarker      = "{\n  \"scan_started\":"
	stdoutJSONEndMarker        = "Removing intermediate container"
)

// Wrapper wraps the Run method.
//
// Run runs a MicroScanner wrapper script and parses the standard output to ScanReport.
type Wrapper interface {
	Run(imageRef, dockerConfig string) (*microscanner.ScanReport, error)
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
func (w *wrapper) Run(imageRef, dockerConfig string) (*microscanner.ScanReport, error) {
	if imageRef == "" {
		return nil, errors.New("image must not be blank")
	}

	runLog := log.WithFields(log.Fields{
		fieldImage:        imageRef,
		fieldDockerConfig: dockerConfig,
	})

	executable, err := exec.LookPath(wrapperScript)
	if err != nil {
		return nil, fmt.Errorf("searching for %s executable: %v", wrapperScript, err)
	}

	runLog.Debugf("Wrapper script executable found at %s", executable)

	stderrBuffer := bytes.Buffer{}

	cmd := exec.Command(executable, imageRef)
	cmd.Stderr = &stderrBuffer
	cmd.Env = []string{
		fmt.Sprintf("DOCKER_CONFIG=%s", filepath.Dir(dockerConfig)),
		fmt.Sprintf("DOCKER_HOST=%s", w.cfg.DockerHost),
		fmt.Sprintf("MICROSCANNER_TOKEN=%s", w.cfg.Token),
		fmt.Sprintf("MICROSCANNER_OPTIONS=%s", w.cfg.Options),
		fmt.Sprintf("USE_LOCAL=%s", "1"),
	}

	runLog.Debug("Running wrapper script")

	stdout, err := cmd.Output()
	if err != nil {
		runLog.WithFields(log.Fields{
			fieldExitCode: cmd.ProcessState.ExitCode(),
			fieldStdErr:   stderrBuffer.String(),
		}).Error("Wrapper script failed")
		return nil, fmt.Errorf("running %s: %v", wrapperScript, err)
	}

	runLog.WithFields(log.Fields{
		fieldExitCode: cmd.ProcessState.ExitCode(),
		fieldStdErr:   stderrBuffer.String(),
	}).Debug("Wrapper script finished")

	return w.GetScanReport(runLog, string(stdout))
}

// GetScanReport parses the standard output of the microscanner-wrapper.sh script, extracts a scan report JSON,
// and returns it as ScanReport.
func (w *wrapper) GetScanReport(runLog *log.Entry, stdout string) (*microscanner.ScanReport, error) {
	out, err := w.extractJSON(runLog, stdout)
	if err != nil {
		return nil, fmt.Errorf("extracting JSON from stdout: %v", err)
	}

	var report microscanner.ScanReport
	err = json.Unmarshal([]byte(out), &report)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling scan report: %v", err)
	}
	return &report, nil
}

func (w *wrapper) extractJSON(runLog *log.Entry, output string) (string, error) {
	if found := strings.Index(output, overridingErrorCodeMessage); found != -1 {
		runLog.Debugf("Removing intermittent message from stdout %s", overridingErrorCodeMessage)
		output = strings.Replace(output, overridingErrorCodeMessage, "", -1)
	}

	start := strings.Index(output, stdoutJSONStartMarker)
	if start == -1 {
		return "", errors.New("cannot find JSON start marker")
	}
	end := strings.LastIndex(output, stdoutJSONEndMarker)
	if end == -1 {
		return "", errors.New("cannot find JSON end marker")
	}

	return output[start:end], nil
}
