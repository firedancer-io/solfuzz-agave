#!/bin/bash

# Fetch protosol
if [ ! -d protosol ]; then
  git clone --depth=1 -q https://github.com/firedancer-io/protosol.git
else
  cd protosol
  git pull -q
  cd ..
fi
