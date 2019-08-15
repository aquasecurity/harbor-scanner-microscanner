package work

import (
	"fmt"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/mocks"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/gocraft/work"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestWorkQueue_ExecuteScanJob(t *testing.T) {
	scanner := mocks.NewScanner()

	scanID := uuid.New()
	scanRequest := harbor.ScanRequest{
		ID:                 scanID.String(),
		RegistryURL:        "docker.io",
		ArtifactRepository: "library/mongo",
		ArtifactDigest:     "sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e",
	}
	scanRequestJSON := fmt.Sprintf(`{
  "id": "%s",
  "registry_url": "docker.io",
  "artifact_repository": "library/mongo",
  "artifact_digest": "sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e"
}`, scanID.String())

	job := &work.Job{
		Args: map[string]interface{}{
			"scanner":      scanner,
			"scan_request": scanRequestJSON,
		},
	}

	scanner.On("Scan", scanRequest).Return(nil)

	queue := &workQueue{}

	err := queue.ExecuteScanJob(job)

	require.NoError(t, err)
	scanner.AssertExpectations(t)
}
