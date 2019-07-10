package image

import (
	"github.com/aquasecurity/harbor-microscanner-adapter/pkg/model/harbor"
	"github.com/aquasecurity/harbor-microscanner-adapter/pkg/model/microscanner"
)

// Scanner defines methods for scanning container images.
type Scanner interface {
	Scan(req harbor.ScanRequest) error
	GetResult(digest string) (*microscanner.ScanResult, error)
}
