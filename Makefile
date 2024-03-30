RUSTFLAGS:=
RUSTFLAGS+=-g
RUSTFLAGS+=-Cpasses=sancov-module
RUSTFLAGS+=-Cllvm-args=-sanitizer-coverage-inline-8bit-counters
RUSTFLAGS+=-Cllvm-args=-sanitizer-coverage-level=4
RUSTFLAGS+=-Cllvm-args=-sanitizer-coverage-pc-table
RUSTFLAGS+=-Cllvm-args=-sanitizer-coverage-trace-compares
RUSTFLAGS+=-Clink-dead-code
RUSTFLAGS+=-Cforce-frame-pointers=yes
RUSTFLAGS+=-Ctarget-feature=-crt-static
CC:=clang

CARGO?=cargo
DOCKER?=docker

.PHONY: build clean dist

build:
	RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) build --target x86_64-unknown-linux-gnu --release --lib

test/self_test: test/self_test.c
	$(CC) -o $@ $< -Werror=all -pedantic -ldl -fsanitize=address,fuzzer-no-link -fsanitize-coverage=inline-8bit-counters

clean:
	$(CARGO) clean

dist:
	mkdir -pv dist && \
    IMAGE=`$(DOCKER) build -q -f ubuntu2004.Dockerfile .` && \
    CONTAINER=`$(DOCKER) create $$IMAGE` && \
    $(DOCKER) cp $$CONTAINER:/app/target/x86_64-unknown-linux-gnu/release/libsolfuzz_agave.so dist/ && \
    $(DOCKER) rm $$CONTAINER
