package microscanner

import (
	"errors"
	"fmt"
	"github.com/aquasecurity/harbor-scanner-microscanner/pkg/model/microscanner"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestWrapper_GetScanReport(t *testing.T) {

	runLog := log.WithFields(log.Fields{
		fieldImage:        "image",
		fieldDockerConfig: "/tmp/.docker",
	})

	stdoutFormat := `Line 1
Line 2
{
  "scan_started": {
  },
  "resources": [
    {
      "resource": {
        "format": "deb",
        "name": "apt",
        "version": "1.8.2",
        "arch": "amd64",
        "cpe": "pkg:/debian:10:apt:1.8.2",
        "name_hash": "583f72a833c7dfd63c03edba3776247a",
        "license": ""
      },
      "scanned": true,
%s
      "vulnerabilities": [
        {
          "name": "CVE-2011-3374",
          "description": "",
          "vendor_url": "https://security-tracker.debian.org/tracker/CVE-2011-3374",
          "vendor_severity": "negligible",
          "vendor_severity_v3": "",
          "classification": "The operating system vendor has classified the issue as a bug rather than a security issue, therefore the vulnerability has been classified as having negligible severity",
          "fix_version": "",
          "nvd_url": "",
          "nvd_severity": "",
          "nvd_severity_v3": ""
        }
      ]
    }
  ]
}
Removing intermediate container
Line 3`
	scanReport := &microscanner.ScanReport{
		Resources: []microscanner.ResourceScan{
			{
				Resource: microscanner.Resource{
					Format:   "deb",
					Name:     "apt",
					Version:  "1.8.2",
					Arch:     "amd64",
					CPE:      "pkg:/debian:10:apt:1.8.2",
					NameHash: "583f72a833c7dfd63c03edba3776247a",
				},
				Scanned: true,
				Vulnerabilities: []microscanner.Vulnerability{
					{
						Name:             "CVE-2011-3374",
						Description:      "",
						VendorURL:        "https://security-tracker.debian.org/tracker/CVE-2011-3374",
						VendorSeverity:   "negligible",
						VendorSeverityV3: "",
						Classification:   "The operating system vendor has classified the issue as a bug rather than a security issue, therefore the vulnerability has been classified as having negligible severity",
						FixVersion:       "",
						NVDURL:           "",
						NVDSeverity:      "",
						NVDSeverityV3:    "",
					},
				},
			},
		},
	}

	testCases := []struct {
		Name string
		Skip string

		Stdout         string
		ExpectedReport *microscanner.ScanReport
		ExpectedError  error
	}{
		{
			Name: "Should return error when JSON start marker is not there",
			Stdout: `Line
Line 2
Line 3`,
			ExpectedError: errors.New("extracting JSON from stdout: cannot find JSON start marker"),
		},
		{
			Name: "Should return error when JSON end marker is not there",
			Stdout: `Line 1
Line 2
{
  "scan_started": {
  }
}
Line 3`,
			ExpectedError: errors.New("extracting JSON from stdout: cannot find JSON end marker"),
		},
		{
			Name:           "Should return scan report",
			Stdout:         fmt.Sprintf(stdoutFormat, ""),
			ExpectedReport: scanReport,
			ExpectedError:  nil,
		},
		{
			Name:           "Should return scan report when stdout contains intermittent message",
			Stdout:         fmt.Sprintf(stdoutFormat, overridingErrorCodeMessage),
			ExpectedReport: scanReport,
			ExpectedError:  nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			if tc.Skip != "" {
				t.Skip(tc.Skip)
			}
			w := &wrapper{}
			report, err := w.GetScanReport(runLog, tc.Stdout)
			assert.Equal(t, tc.ExpectedReport, report)
			assert.Equal(t, err, tc.ExpectedError)
		})
	}

}
