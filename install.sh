#!/usr/bin/env bash

set -e

python3.11 -m venv solfuzz_agave_env
source solfuzz_agave_env/bin/activate
pip3 install -r requirements.txt
