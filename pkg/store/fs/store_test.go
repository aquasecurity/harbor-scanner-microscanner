package fs

import (
	"github.com/danielpacak/harbor-scanner-contract/pkg/model/harbor"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestFsStore_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping an integration test")
	}

	// TODO Write and read from a temporary dir
	store, err := NewStore("/tmp/harbor")
	require.NoError(t, err)
	t.Logf("store: %v", store)

	scanID, _ := uuid.NewRandom()

	err = store.Save(scanID, &harbor.ScanResult{
		Severity: harbor.SevMedium,
		Vulnerabilities: []*harbor.VulnerabilityItem{
			{ID: "CVE-1"},
		},
	})
	require.NoError(t, err)

	sr, err := store.Get(scanID)
	require.NoError(t, err)
	t.Logf("sr: %v", sr)
}
