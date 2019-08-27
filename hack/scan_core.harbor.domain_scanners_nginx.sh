#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

${DIR}/scan.sh "core.harbor.domain" "scanners/nginx" "sha256:099019968725f0fc12c4b69b289a347ae74cc56da0f0ef56e8eb8e0134fc7911"
