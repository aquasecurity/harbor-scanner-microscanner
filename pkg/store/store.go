package store

import (
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/microscanner"
	"github.com/google/uuid"
)

// Scan represents a scan status and associated data.
type ScanReports struct {
	HarborVulnerabilityReport *harbor.VulnerabilityReport `json:"harbor_vulnerability_report"`
	MicroScannerReport        *microscanner.ScanReport    `json:"micro_scanner_report"`
}

// DataStore defines methods for saving and retrieving scan jobs and scan reports.
type DataStore interface {
	SaveScanJob(scanID uuid.UUID, scanJob *job.ScanJob) error
	GetScanJob(scanID uuid.UUID) (*job.ScanJob, error)
	UpdateJobStatus(scanID uuid.UUID, currentStatus, newStatus job.ScanJobStatus) error
	SaveScanReports(scanID uuid.UUID, scanReports *ScanReports) error
	GetScanReports(scanID uuid.UUID) (*ScanReports, error)
}
