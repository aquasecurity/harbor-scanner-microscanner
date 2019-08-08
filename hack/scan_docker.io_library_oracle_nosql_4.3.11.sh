#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

${DIR}/scan.sh "docker.io" "library/oracle/nosql" "sha256:df0dc81e03cb1ea29dd68124608fbea35a16dd954ae2e0a6acdeecd739721e8e"
