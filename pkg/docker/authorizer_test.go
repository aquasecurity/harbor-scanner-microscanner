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
	authorizer := NewAuthorizer()
	configFileName, err := authorizer.Authorize(harbor.ScanRequest{
		RegistryURL:           "core.harbor.domain",
		RegistryAuthorization: "JWTTOKENGOESHERE",
	})
	require.NoError(t, err)
	configFile, err := os.Open(configFileName)
	require.NoError(t, err)
	bytes, err := ioutil.ReadAll(configFile)

	configJSON := `{
 "auths": {
   "core.harbor.domain": {
     "registrytoken":"JWTTOKENGOESHERE"
   }
 },
 "HttpHeaders": {
   "User-Agent":"Harbor Scanner Microscanner"
 }
}`

	assert.JSONEq(t, configJSON, string(bytes))
	err = os.RemoveAll(filepath.Dir(configFileName))
	require.NoError(t, err)
}
