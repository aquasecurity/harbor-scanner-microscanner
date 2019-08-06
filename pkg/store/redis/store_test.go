package redis

import (
	"github.com/danielpacak/harbor-scanner-microscanner/pkg/etc"
	"github.com/danielpacak/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/danielpacak/harbor-scanner-microscanner/pkg/model/microscanner"
	"github.com/danielpacak/harbor-scanner-microscanner/pkg/store"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRedisStore_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping an integration test")
	}

	store, err := NewStore(&etc.RedisStoreConfig{
		RedisURL:  "redis://localhost:6379",
		Namespace: "harbor.scanner.microscanner:store",
	})
	require.NoError(t, err)

	scanID, err := uuid.NewRandom()
	require.NoError(t, err)

	t.Logf("Saving scanID: %s", scanID.String())
	err = store.Save(scanID, &harbor.VulnerabilitiesReport{
		Severity: harbor.SevHigh,
		Vulnerabilities: []*harbor.VulnerabilityItem{
			{
				ID:       "CVE-247-213",
				Severity: harbor.SevHigh,
				Pkg:      "apt",
				Version:  "10.0.2",
			},
			{
				ID:       "CVE-129-008",
				Severity: harbor.SevMedium,
				Pkg:      "openssl",
				Version:  "3.1",
			},
		},
	})
	require.NoError(t, err)

	t.Logf("Retrieving scanID: %s", scanID.String())
	hsr, err := store.Get(scanID)
	require.NoError(t, err)
	t.Logf("hsr: %v", hsr)
}

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
		Foo: "Bar",
		HarborReport: &harbor.VulnerabilitiesReport{
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
	t.Logf("scan: %v", scan)
}
