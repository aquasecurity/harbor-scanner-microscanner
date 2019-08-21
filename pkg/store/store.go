package store

import (
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/microscanner"
	"github.com/google/uuid"
)

// ScanReports represents scan reports in MicroScanner and Harbor format.
type ScanReports struct {
	HarborVulnerabilityReport *harbor.VulnerabilityReport `json:"harbor_vulnerability_report"`
	MicroScannerReport        *microscanner.ScanReport    `json:"micro_scanner_report"`
}

// DataStore defines methods for saving and retrieving ScanJobs and ScanReports.
type DataStore interface {
	// SaveScanJob saves a given ScanJob associated with the given scan identifier.
	SaveScanJob(scanID uuid.UUID, scanJob *job.ScanJob) error
	// GetScanJob gets a ScanJob associated with the given scan identifier.
	GetScanJob(scanID uuid.UUID) (*job.ScanJob, error)
	// UpdateScanJobStatus updates the status of the ScanJob associated with the given scan identifier.
	// Returns an error when the actual state of the ScanJob is different then the specified currentStatus.
	UpdateScanJobStatus(scanID uuid.UUID, currentStatus, newStatus job.ScanJobStatus) error
	// SaveScanReports saves given ScanReports associated with the given scan identifier.
	SaveScanReports(scanID uuid.UUID, scanReports *ScanReports) error
	// GetScanReports gets ScanReports associated with the given scan identifier.
	GetScanReports(scanID uuid.UUID) (*ScanReports, error)
}
