#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail

main_dependencies=$(poetry show --only main)

if [[ "$main_dependencies" ]]; then
    exit 1
else
    exit 0
fi
