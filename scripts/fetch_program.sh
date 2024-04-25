#!/bin/bash

if [ -z "$1" ]; then
    echo "Error: Program name argument is missing."
    exit 1
fi

mkdir -p programs

if [ -d "programs/$1" ]; then
    echo "Updating program $1...";
    (cd programs/$1 && git fetch && git pull);
else
    echo "Cloning program $1...";
    git clone https://github.com/solana-program/$1 programs/$1;
fi

cargo build-sbf --manifest-path=programs/$1/program/Cargo.toml --sbf-out-dir programs