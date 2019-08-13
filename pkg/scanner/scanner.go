package scanner

import (
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/microscanner"
)

// Scanner defines methods for scanning artifacts.
type Scanner interface {
	GetMetadata() (*harbor.ScannerMetadata, error)
	Scan(req harbor.ScanRequest) error
	GetHarborVulnerabilityReport(scanRequestID string) (*harbor.VulnerabilityReport, error)
	GetMicroScannerReport(scanRequestID string) (*microscanner.ScanReport, error)
}
