// +build integration

package redis

import (
	"context"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/etc"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/job"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/microscanner"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tc "github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"testing"
)

func TestRedisStore_ScanCRUD(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping an integration test")
	}

	ctx := context.Background()
	redisC, err := tc.GenericContainer(ctx, tc.GenericContainerRequest{
		ContainerRequest: tc.ContainerRequest{
			Image:        "redis:5.0.5",
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForLog("Ready to accept connections"),
		},
		Started: true,
	})
	require.NoError(t, err)
	defer redisC.Terminate(ctx)
	host, err := redisC.Host(ctx)
	require.NoError(t, err)
	port, err := redisC.MappedPort(ctx, "6379")
	require.NoError(t, err)

	redisURL := fmt.Sprintf("redis://%s:%d", host, port.Int())
	t.Logf("Redis URL: %s", redisURL)

	dataStore, err := NewDataStore(&etc.RedisStoreConfig{
		RedisURL:  redisURL,
		Namespace: "harbor.scanner.microscanner:store",
		Pool: &etc.PoolConfig{
			MaxActive: 5,
			MaxIdle:   5,
		},
	})
	require.NoError(t, err)

	t.Run("Should save and get ScanJob", func(t *testing.T) {
		scanJobID := uuid.New().String()
		err := dataStore.SaveScanJob(&job.ScanJob{
			ID:     scanJobID,
			Status: job.Queued,
		})
		require.NoError(t, err)

		j, err := dataStore.GetScanJob(scanJobID)
		require.NoError(t, err)
		assert.Equal(t, &job.ScanJob{
			ID:     scanJobID,
			Status: job.Queued,
		}, j)

		err = dataStore.UpdateStatus(scanJobID, job.Pending, job.Finished)
		assert.EqualError(t, err, "expected status Pending but was Queued")

		err = dataStore.UpdateStatus(scanJobID, job.Queued, job.Pending)
		require.NoError(t, err)

		j, err = dataStore.GetScanJob(scanJobID)
		assert.Equal(t, &job.ScanJob{
			ID:     scanJobID,
			Status: job.Pending,
		}, j)

		scanReports := job.ScanReports{
			HarborVulnerabilityReport: &harbor.VulnerabilityReport{
				Severity: harbor.SevHigh,
				Vulnerabilities: []*harbor.VulnerabilityItem{
					{
						ID: "CVE-2013-1400",
					},
				},
			},
			MicroScannerReport: &microscanner.ScanReport{
				Resources: []microscanner.ResourceScan{
					{
						Vulnerabilities: []microscanner.Vulnerability{
							{
								Name: "CVE-2013-1400",
							},
						},
					},
				},
			},
		}

		err = dataStore.UpdateReports(scanJobID, scanReports)
		require.NoError(t, err)

		j, err = dataStore.GetScanJob(scanJobID)
		require.NoError(t, err)
		assert.Equal(t, scanReports, *j.Reports)
	})

}
