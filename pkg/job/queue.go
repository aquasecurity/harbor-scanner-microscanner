package job

import (
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/google/uuid"
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

type ScanJob struct {
	ID     string        `json:"id"`
	Status ScanJobStatus `json:"status"`
}

// Queue manages execution of ScanJobs.
type Queue interface {
	// Start starts this queue.
	Start()
	// Stop stops this queue.
	Stop()
	// EnqueueScanJob enqueues a ScanJob for the given ScanRequest.
	EnqueueScanJob(sr harbor.ScanRequest) (*ScanJob, error)
	// GetScanJob returns a ScanJob associated with the given scan request identifier.
	GetScanJob(scanID uuid.UUID) (*ScanJob, error)
}
