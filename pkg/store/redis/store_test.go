package redis

import (
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/microscanner"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/store"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRedisStore(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping an integration test")
	}

	dataStore, err := NewStore(&etc.RedisStoreConfig{
		RedisURL:  "redis://localhost:6379",
		Namespace: "harbor.scanner.microscanner:store",
		Pool: &etc.PoolConfig{
			MaxActive: 5,
			MaxIdle:   5,
		},
	})
	require.NoError(t, err)

	t.Run("Should save and then retrieve scan job", func(t *testing.T) {
		scanID := uuid.New()
		err := dataStore.SaveScanJob(scanID, &job.ScanJob{
			ID:     scanID.String(),
			Status: job.Pending,
		})
		require.NoError(t, err)

		scanJob, err := dataStore.GetScanJob(scanID)
		require.NoError(t, err)
		assert.Equal(t, &job.ScanJob{
			ID:     scanID.String(),
			Status: job.Pending,
		}, scanJob)
	})

	t.Run("Should save and then retrieve scan reports", func(t *testing.T) {
		scanID := uuid.New()
		err = dataStore.SaveScanReports(scanID, &store.ScanReports{
			HarborVulnerabilityReport: &harbor.VulnerabilityReport{
				Severity:        harbor.SevHigh,
				Vulnerabilities: []*harbor.VulnerabilityItem{},
			},
			MicroScannerReport: &microscanner.ScanReport{
				Digest: "ABC",
			},
		})
		require.NoError(t, err)

		scanReports, err := dataStore.GetScanReports(scanID)
		require.NoError(t, err)
		require.NotNil(t, scanReports)

		scanReports, err = dataStore.GetScanReports(uuid.New())
		require.NoError(t, err)
		require.Nil(t, scanReports)
	})
}
