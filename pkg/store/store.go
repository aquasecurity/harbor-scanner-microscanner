package store

import (
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/microscanner"
)

// ScanReports represents scan reports in MicroScanner and Harbor format.
// TODO Add as property to ScanJob
type ScanReports struct {
	HarborVulnerabilityReport *harbor.VulnerabilityReport `json:"harbor_vulnerability_report"`
	MicroScannerReport        *microscanner.ScanReport    `json:"micro_scanner_report"`
}

// DataStore defines methods for saving and retrieving ScanJobs and ScanReports.
type DataStore interface {
	// SaveScanJob saves a given ScanJob associated with the given scan identifier.
	SaveScanJob(scanID string, scanJob *job.ScanJob) error
	// GetScanJob gets a ScanJob associated with the given scan identifier.
	GetScanJob(scanID string) (*job.ScanJob, error)
	// UpdateScanJobStatus updates the status of the ScanJob associated with the given scan identifier.
	// Returns an error when the actual state of the ScanJob is different then the specified currentStatus.
	UpdateScanJobStatus(scanID string, currentStatus, newStatus job.ScanJobStatus) error
	// SaveScanReports saves given ScanReports associated with the given scan identifier.
	SaveScanReports(scanID string, scanReports *ScanReports) error
	// GetScanReports gets ScanReports associated with the given scan identifier.
	GetScanReports(scanID string) (*ScanReports, error)
}
