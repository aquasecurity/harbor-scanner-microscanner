#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

${DIR}/scan.sh "docker.io" "library/mongo" "sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e"
