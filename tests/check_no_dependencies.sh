#!/bin/bash
if [[ $(poetry show --no-dev) ]]; then
    exit 1
else
    exit 0
fi
