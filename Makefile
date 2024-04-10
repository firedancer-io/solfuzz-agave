include corebpf.mk

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

BUILD_TARGET?=x86_64-unknown-linux-gnu

CORE_BPF_PROGRAM_ID?=

.PHONY: build clean

build:
	@if [ ! -z "$(CORE_BPF_PROGRAM_ID)" ]; then \
		echo "Compiling SolFuzz-Agave with Core BPF program $(CORE_BPF_PROGRAM_ID)"; \
		if [ "$(CORE_BPF_PROGRAM_ID)" = "AddressLookupTab1e1111111111111111111111111" ]; then \
			$(MAKE) AddressLookupTable; \
			LIB_FEATURES="--features core-bpf-address-lookup-table"; \
		elif [ "$(CORE_BPF_PROGRAM_ID)" = "Config1111111111111111111111111111111111111" ]; then \
			$(MAKE) Config; \
			LIB_FEATURES="--features core-bpf-config"; \
		else \
			echo "Core BPF program not supported: $(CORE_BPF_PROGRAM_ID)"; \
			exit 1; \
		fi; \
		RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) build --target $(BUILD_TARGET) --release --lib $$LIB_FEATURES; \
	else \
		RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) build --target $(BUILD_TARGET) --release --lib; \
	fi

test/self_test: test/self_test.c
	$(CC) -o $@ $< -Werror=all -pedantic -ldl -fsanitize=address,fuzzer-no-link -fsanitize-coverage=inline-8bit-counters

clean:
	$(CARGO) clean
