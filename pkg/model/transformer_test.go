package model

import (
	"github.com/danielpacak/harbor-scanner-microscanner/pkg/model/microscanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestTransformer_Transform(t *testing.T) {
	transformer := NewTransformer()
	hsr, err := transformer.Transform(&microscanner.ScanReport{
		Resources: []microscanner.ResourceScan{
			{
				Resource: microscanner.Resource{
					Format:  "deb",
					Name:    "apt",
					Version: "1.0.9.8.5",
				},
				Vulnerabilities: []microscanner.Vulnerability{
					{
						Name: "CVE-2011-3374",
					},
				},
			},
		},
	})
	require.NoError(t, err)
	assert.NotNil(t, hsr)
}
