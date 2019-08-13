package redis

import (
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/microscanner"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/store"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRedisStore_ScanCRUD(t *testing.T) {
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

	id := uuid.New()
	err = dataStore.SaveScan(id, &store.Scan{
		HarborVulnerabilityReport: &harbor.VulnerabilityReport{
			Severity:        harbor.SevHigh,
			Vulnerabilities: []*harbor.VulnerabilityItem{},
		},
		MicroScannerReport: &microscanner.ScanReport{
			Digest: "ABC",
		},
	})
	require.NoError(t, err)

	scan, err := dataStore.GetScan(id)
	require.NoError(t, err)
	require.NotNil(t, scan)

	scan, err = dataStore.GetScan(uuid.New())
	require.NoError(t, err)
	require.Nil(t, scan)
}
