package redis

import (
	"github.com/danielpacak/harbor-scanner-contract/pkg/model/harbor"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRedisStore_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping an integration test")
	}

	store, err := NewStore("redis://localhost:6379")
	require.NoError(t, err)

	scanID, err := uuid.NewRandom()
	require.NoError(t, err)

	t.Logf("Saving scanID: %s", scanID.String())
	err = store.Save(scanID, &harbor.ScanResult{
		Severity: harbor.SevHigh,
		Overview: &harbor.ComponentsOverview{
			Total: 2,
			Summary: []*harbor.ComponentsOverviewEntry{
				{Sev: int(harbor.SevHigh), Count: 1},
				{Sev: int(harbor.SevMedium), Count: 1},
			},
		},
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
