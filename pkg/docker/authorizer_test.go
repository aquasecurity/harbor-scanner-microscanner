package docker

import (
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/harbor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestAuthorizer_Authorize(t *testing.T) {
	testCases := []struct {
		Name string

		Authorization      string
		ExpectedConfigJSON string
		ExpectedError      string
	}{
		{
			Name:          "Should authorize with Basic authorization",
			Authorization: "Basic aGFyYm9yOnMzY3JldA==",
			ExpectedConfigJSON: `{
 "auths": {
   "core.harbor.domain": {
     "auth": "aGFyYm9yOnMzY3JldA=="
   }
 },
 "HttpHeaders": {
   "User-Agent": "Harbor Scanner MicroScanner"
 }
}`,
		},
		{
			Name:          "Should authorize with Bearer authorization",
			Authorization: "Bearer JWTTOKENGOESHERE",
			ExpectedConfigJSON: `{
 "auths": {
   "core.harbor.domain": {
     "registrytoken": "JWTTOKENGOESHERE"
   }
 },
 "HttpHeaders": {
   "User-Agent": "Harbor Scanner MicroScanner"
 }
}`,
		},
		{
			Name:          "Should return error when authorization has invalid format",
			Authorization: "THIS_IS_INVALID",
			ExpectedError: "parsing authorization: expected format <type> <credentials>: got: THIS_IS_INVALID",
		},
		{
			Name:          "Should return error with unknown authorization type",
			Authorization: "Unknown s3cret",
			ExpectedError: "unrecognized authorization type: Unknown",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			configFileName, err := NewAuthorizer().Authorize(harbor.ScanRequest{
				Registry: harbor.Registry{
					URL:           "core.harbor.domain",
					Authorization: tc.Authorization,
				},
			})

			if tc.ExpectedError != "" {
				assert.EqualError(t, err, tc.ExpectedError)
			}

			if err == nil {
				configFile, err := os.Open(configFileName)
				require.NoError(t, err)
				bytes, err := ioutil.ReadAll(configFile)

				assert.JSONEq(t, tc.ExpectedConfigJSON, string(bytes))

				err = os.RemoveAll(filepath.Dir(configFileName))
				require.NoError(t, err)
			}
		})
	}

}
