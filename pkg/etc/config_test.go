package etc

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestGetConfig(t *testing.T) {

	testCases := []struct {
		Name string

		Envs map[string]string

		ExpectedConfig *Config
		ExpectedError  error
	}{
		{
			Name:          "Should return error when token is not set",
			ExpectedError: errors.New("env SCANNER_MICROSCANNER_TOKEN not set"),
		},
		{
			Name: "Should return default config",
			Envs: map[string]string{"SCANNER_MICROSCANNER_TOKEN": "s3cret"},
			ExpectedConfig: &Config{
				APIAddr: ":8080",
				MicroScanner: &MicroScannerConfig{
					DockerHost: "tcp://localhost:2375",
					Options:    "--continue-on-failure --full-output",
					Token:      "s3cret",
				},
				RedisStore: &RedisStoreConfig{
					RedisURL:  defaultRedisURL,
					Namespace: "harbor.scanner.microscanner:store",
					Pool: &PoolConfig{
						MaxActive: 5,
						MaxIdle:   5,
					},
				},
				JobQueue: &JobQueueConfig{
					RedisURL:          defaultRedisURL,
					Namespace:         "harbor.scanner.microscanner:job-queue",
					WorkerConcurrency: 1,
					Pool: &PoolConfig{
						MaxActive: 5,
						MaxIdle:   5,
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			setenvs(t, tc.Envs)
			cfg, err := GetConfig()
			assert.Equal(t, tc.ExpectedError, err)
			assert.Equal(t, tc.ExpectedConfig, cfg)
		})
	}

}

func setenvs(t *testing.T, envs map[string]string) {
	t.Helper()
	os.Clearenv()
	for key, value := range envs {
		err := os.Setenv(key, value)
		require.NoError(t, err)
	}
}
