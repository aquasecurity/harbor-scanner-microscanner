#!/usr/bin/env bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

${DIR}/scan.sh "quay.io" "coreos/clair" "sha256:303c7b22e1778acb7c624cca01bad8d3bc5a1b25922d59d28908f223639d9722"
