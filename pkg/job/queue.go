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

// Queue manages execution of scan jobs.
type Queue interface {
	// Start starts this queue.
	Start()
	// Stop stops this queue.
	Stop()
	// EnqueueScanJob enqueues a scan job for the given scan request.
	EnqueueScanJob(sr harbor.ScanRequest) (*ScanJob, error)
	// GetScanJob returns a scan job for the given scan request ID
	GetScanJob(scanRequestID uuid.UUID) (*ScanJob, error)
}
