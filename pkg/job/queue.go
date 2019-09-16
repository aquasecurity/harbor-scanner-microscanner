package job

import (
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/microscanner"
)

type ScanJobStatus int

const (
	Queued ScanJobStatus = iota
	Pending
	Finished
	Failed
)

func (s ScanJobStatus) String() string {
	return [...]string{"Queued", "Pending", "Finished", "Failed"}[s]
}

// ScanReports represents scan reports in MicroScanner and Harbor format.
type ScanReports struct {
	HarborVulnerabilityReport *harbor.VulnerabilityReport `json:"harbor_vulnerability_report"`
	MicroScannerReport        *microscanner.ScanReport    `json:"micro_scanner_report"`
}

// ScanJob represents a task of handling a given ScanRequest.
type ScanJob struct {
	ID      string        `json:"id"`
	Status  ScanJobStatus `json:"status"`
	Reports *ScanReports  `json:"reports"`
	// TODO Add Artifact field
	// TODO Add Error field
}

// Queue manages execution of ScanJobs.
// TODO(refactor) Split Queue into ScanEnqueuer and ScanWorker
type Queue interface {
	// Start starts this queue.
	Start()
	// Stop stops this queue.
	Stop()
	// EnqueueScanJob enqueues a ScanJob for the given ScanRequest.
	EnqueueScanJob(sr harbor.ScanRequest) (*ScanJob, error)
}
