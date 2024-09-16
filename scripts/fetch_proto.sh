#!/bin/bash

# Fetch protosol (TODO: take out checkout once protosol branch is merged)
if [ ! -d protosol ]; then
  git clone --depth=1 -b  -q https://github.com/firedancer-io/protosol.git
  cd protosol
  git checkout runtime_fuzz_v2_updates
  cd ..
else
  cd protosol
  git pull -q
  cd ..
fi
