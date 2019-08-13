package store

import (
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/microscanner"
	"github.com/google/uuid"
)

// DataStore defines methods for saving and retrieving scan reports.
//
// Save saves the given ScanResult with the given scanID.
// Get retrieves ScanResult for the given scanID.
type DataStore interface {
	SaveScan(scanID uuid.UUID, scan *Scan) error
	GetScan(scanID uuid.UUID) (*Scan, error)
}

// Scan represents a scan status and associated data.
type Scan struct {
	JobID                     string                      `json:"job_id"`
	HarborVulnerabilityReport *harbor.VulnerabilityReport `json:"harbor_vulnerability_report"`
	MicroScannerReport        *microscanner.ScanReport    `json:"micro_scanner_report"`
}
