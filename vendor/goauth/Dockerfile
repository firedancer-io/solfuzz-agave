FROM ubuntu:xenial
MAINTAINER Drazen Urch <github@drazenur.ch>

ARG RUST_VER=nightly

ENV USER root

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       build-essential \
       ca-certificates \
       curl \
       musl-tools \
       git \
       libssl-dev \
       pkg-config

RUN curl -sO https://static.rust-lang.org/dist/rust-${RUST_VER}-x86_64-unknown-linux-gnu.tar.gz && \
    tar -xzf rust-${RUST_VER}-x86_64-unknown-linux-gnu.tar.gz && \
    ./rust-${RUST_VER}-x86_64-unknown-linux-gnu/install.sh --without=rust-docs && \
    curl -sO https://static.rust-lang.org/dist/rust-std-${RUST_VER}-x86_64-unknown-linux-musl.tar.gz && \
    tar -xzf rust-std-${RUST_VER}-x86_64-unknown-linux-musl.tar.gz && \
    ./rust-std-${RUST_VER}-x86_64-unknown-linux-musl/install.sh --without=rust-docs

RUN DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y curl && \
    DEBIAN_FRONTEND=noninteractive apt-get autoremove -y

RUN rm -rf \
    rust-std-${RUST_VER}-x86_64-unknown-linux-musl \
    rust-${RUST_VER}-x86_64-unknown-linux-gnu \
    rust-std-${RUST_VER}-x86_64-unknown-linux-musl.tar.gz \
    rust-${RUST_VER}-x86_64-unknown-linux-gnu.tar.gz \
    /var/lib/apt/lists/* \
    /tmp/* \
    /var/tmp/*

ADD . /code
WORKDIR /code



