package scanner

import (
	"github.com/danielpacak/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/danielpacak/harbor-scanner-microscanner/pkg/model/microscanner"
)

// Scanner defines methods for scanning artifacts.
type Scanner interface {
	GetMetadata() (*harbor.ScannerMetadata, error)
	SubmitScan(req harbor.ScanRequest) error
	GetScanReportHarbor(scanRequestID string) (*harbor.VulnerabilitiesReport, error)
	GetScanReportRaw(scanRequestID string) (*microscanner.ScanReport, error)
}
