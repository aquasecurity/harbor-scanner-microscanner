#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

${DIR}/scan.sh "docker.io" "library/debian" "sha256:fe4612b98b35c8ae4719a6a8d5e98432b4b297767a8aebfd858c48f98ecebb7b"
