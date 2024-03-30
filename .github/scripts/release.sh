#!/usr/bin/env bash

set -e

if [[ -z "$1" ]]; then
  echo "Usage: $0 <version>"
  exit 1
fi

VERSION=$1

make dist DOCKER=podman
rm -rf dist/github
mkdir -p dist/github

ln -f dist/libsolfuzz_agave_sancov.so dist/github/libsolfuzz_agave_${VERSION}_amd64_focal_sancov.so
gzip -kf dist/github/libsolfuzz_agave_${VERSION}_amd64_focal_sancov.so
rm -f dist/github/libsolfuzz_agave_${VERSION}_amd64_focal_sancov.so

ln -f dist/libsolfuzz_agave.so dist/github/libsolfuzz_agave_${VERSION}_amd64_focal.so
gh release create ${VERSION} dist/github/*
