#!/usr/bin/env bash

set -euo pipefail

# Install prefix
PREFIX="$(pwd)/opt"

install_flatbuffers () {
  mkdir -p "$PREFIX/build/flatbuffers"
  echo "[+] Configuring flatbuffers (flatc only)"
  cmake \
    -S shlr/flatbuffers \
    -B "$PREFIX/build/flatbuffers" \
    -G"Unix Makefiles" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX:PATH="$PREFIX" \
    -DFLATBUFFERS_BUILD_TESTS=OFF \
    -DFLATBUFFERS_BUILD_FLATC=ON \
    -DFLATBUFFERS_BUILD_FLATLIB=OFF

  echo "[+] Building flatc binary only"
  make -C "$PREFIX/build/flatbuffers" flatc -j `nproc`

  echo "[+] Installing flatc via cmake"
  cmake --install "$PREFIX/build/flatbuffers" --config Release

  echo "[+] Successfully installed flatc"
}

install_protobuf () {
  mkdir -p "$PREFIX/build/protobuf"

  # Note: insane CMAKE_CXX_LINK_EXECUTABLE required to link with custom libc++
  echo "[+] Configuring protobuf"
  cmake \
    -S shlr/protobuf \
    -B "$PREFIX/build/protobuf" \
    -G"Unix Makefiles" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX:PATH="$PREFIX" \
    -DCMAKE_INSTALL_LIBDIR="lib" \
    -DABSL_PROPAGATE_CXX_STD=ON \
    -DBUILD_TESTING=OFF \
    -Dprotobuf_BUILD_TESTS=OFF \
    -Dprotobuf_BUILD_CONFORMANCE=OFF \
    -Dprotobuf_BUILD_EXAMPLES=OFF \
    -Dprotobuf_BUILD_PROTOBUF_BINARIES=ON \
    -Dprotobuf_BUILD_PROTOC_BINARIES=ON \
    -Dprotobuf_BUILD_LIBPROTOC=ON \
    -Dprotobuf_BUILD_SHARED_LIBS=OFF \
    -Dprotobuf_INSTALL=ON

  echo "[+] Building protobuf"
  make -C "$PREFIX/build/protobuf" -j `nproc`

  echo "[+] Installing protobuf"
  make -C "$PREFIX/build/protobuf" install -j `nproc`
  echo "[+] Successfully installed protobuf"
}

mkdir -pv "$PREFIX"
install_flatbuffers
install_protobuf
