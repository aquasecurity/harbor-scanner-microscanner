#!/usr/bin/env bash

REGISTRY_URL=$1
ARTIFACT_REPOSITORY=$2
ARTIFACT_DIGEST=$3

# 1. Generate a unique identifier for a sample scan request:
SCAN_REQUEST_ID=$(uuidgen | tr "[:upper:]" "[:lower:]")

# 2. Submit the scan request:

curl http://localhost:8080/api/v1/scan \
-H 'Content-Type: application/vnd.scanner.adapter.scan.request+json; version=1.0' \
-d @- << EOF
{
  "id": "${SCAN_REQUEST_ID}",
  "registry": {
    "url": "${REGISTRY_URL}",
    "authorization": "${REGISTRY_AUTHORIZATION}"
  },
  "artifact": {
    "repository": "${ARTIFACT_REPOSITORY}",
    "digest": "${ARTIFACT_DIGEST}"
  }
}
EOF

# 3. Get scan report:
echo "curl -v -H 'Accept: application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0' http://localhost:8080/api/v1/scan/${SCAN_REQUEST_ID}/report"
echo "curl -v -H 'Accept: application/vnd.scanner.adapter.vuln.report.raw' http://localhost:8080/api/v1/scan/${SCAN_REQUEST_ID}/report"
