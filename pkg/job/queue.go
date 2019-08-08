package job

import "github.com/danielpacak/harbor-scanner-microscanner/pkg/model/harbor"

type Queue interface {
	Start()
	Stop()
	SubmitScanImageJob(sr harbor.ScanRequest) (string, error)
}
