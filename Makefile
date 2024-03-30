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

.PHONY: build build_base build_sancov clean dist

build: build_base build_sancov

build_base:
	RUSTFLAGS="" $(CARGO) build --release --lib

build_sancov:
	RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) build --target x86_64-unknown-linux-gnu --release --lib

test/self_test: test/self_test.c
	$(CC) -o $@ $< -Werror=all -pedantic -ldl -fsanitize=address,fuzzer-no-link -fsanitize-coverage=inline-8bit-counters

clean:
	$(CARGO) clean

dist:
	mkdir -pv dist && \
    IMAGE=`$(DOCKER) build -q -f ubuntu2004.Dockerfile .` && \
    CONTAINER=`$(DOCKER) create $$IMAGE` && \
    $(DOCKER) cp $$CONTAINER:/app/target/x86_64-unknown-linux-gnu/release/libsolfuzz_agave.so dist/libsolfuzz_agave_sancov.so && \
    $(DOCKER) cp $$CONTAINER:/app/target/release/libsolfuzz_agave.so dist/libsolfuzz_agave.so && \
    $(DOCKER) rm $$CONTAINER
