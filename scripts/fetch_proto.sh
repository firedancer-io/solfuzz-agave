#!/bin/bash

# Fetch protosol (TODO: take out checkout once protosol branch is merged)
if [ ! -d protosol ]; then
  git clone --depth=1 -b runtime_fuzz_v2_updates -q https://github.com/firedancer-io/protosol.git
else
  cd protosol
  git pull -q
  cd ..
fi
