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
)

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

	stderrBuffer := bytes.Buffer{}
	stdoutBuffer := bytes.Buffer{}

	log.Debugf("Started scanning %s", image)

	executable, err := exec.LookPath(wrapperScript)
	if err != nil {
		return nil, fmt.Errorf("searching for %s executable: %v", wrapperScript, err)
	}
	log.Debugf("Wrapper script executable found at %s", executable)

	cmd := exec.Command(executable, image)
	cmd.Stderr = &stderrBuffer
	cmd.Stdout = &stdoutBuffer
	cmd.Env = []string{
		fmt.Sprintf("DOCKER_HOST=%s", w.cfg.DockerHost),
		fmt.Sprintf("MICROSCANNER_TOKEN=%s", w.cfg.Token),
		fmt.Sprintf("MICROSCANNER_OPTIONS=%s", w.cfg.Options),
		fmt.Sprintf("USE_LOCAL=%s", "1"),
	}

	err = cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("running %s: %v", wrapperScript, err)
	}

	log.Debugf("%s exit code %d", wrapperScript, cmd.ProcessState.ExitCode())
	if output := stderrBuffer.String(); output != "" {
		log.Errorf("%s: %s", wrapperScript, output)
	}

	log.Debugf("Finished scanning %s", image)
	out := w.extractJSON(stdoutBuffer)

	var sr microscanner.ScanReport
	err = json.Unmarshal([]byte(out), &sr)
	if err != nil {
		return nil, fmt.Errorf("unmarshalling microscanner scan report: %v", err)
	}
	return &sr, nil
}

func (w *wrapper) extractJSON(stdoutBuffer bytes.Buffer) string {
	output := stdoutBuffer.String()
	start := strings.Index(output, "{\n  \"scan_started\":")
	end := strings.LastIndex(output, "Removing intermediate container")
	return output[start:end]
}
