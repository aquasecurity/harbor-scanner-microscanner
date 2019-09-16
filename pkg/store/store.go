package store

import (
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job"
)

// DataStore defines methods for persisting ScanJobs.
type DataStore interface {
	// SaveScanJob saves a given ScanJob.
	SaveScanJob(scanJob *job.ScanJob) error
	// GetScanJob gets a ScanJob for the specified identifier.
	GetScanJob(scanJobID string) (*job.ScanJob, error)
	// UpdateStatus updates the status of the specified ScanJob.
	// Returns an error when the actual state of the ScanJob is different then the specified currentStatus.
	UpdateStatus(scanJobID string, currentStatus, newStatus job.ScanJobStatus) error
	// UpdateScanReports updates the ScanReports of the specified ScanJob.
	UpdateReports(scanJobID string, reports job.ScanReports) error
}
