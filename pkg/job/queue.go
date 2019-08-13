package job

import "github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"

type Queue interface {
	Start()
	Stop()
	EnqueueScanJob(sr harbor.ScanRequest) (string, error)
}
