package image

import "github.com/aquasecurity/microscanner-proxy/pkg/model"

// Scanner defines methods for scanning container images.
type Scanner interface {
	Scan(req model.ScanRequest) error
	GetResults(correlationID string) (*model.ScanResult, error)
}
