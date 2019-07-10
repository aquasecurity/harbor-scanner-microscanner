package image

import (
	"github.com/aquasecurity/harbor-microscanner-adapter/pkg/model/harbor"
)

// Scanner defines methods for scanning container images.
type Scanner interface {
	Scan(req harbor.ScanRequest) (*harbor.ScanResponse, error)
	GetResult(detailsKey string) (*harbor.ScanResult, error)
}
