# Base flags for fuzzing instrumentation
RUSTFLAGS_BASE:=
RUSTFLAGS_BASE+=-g
RUSTFLAGS_BASE+=-Cpasses=sancov-module
RUSTFLAGS_BASE+=-Cllvm-args=-sanitizer-coverage-level=4
RUSTFLAGS_BASE+=-Cllvm-args=-sanitizer-coverage-pc-table
RUSTFLAGS_BASE+=-Clink-dead-code
RUSTFLAGS_BASE+=-Cforce-frame-pointers=yes
RUSTFLAGS_BASE+=-Ctarget-feature=-crt-static

# 8-bit counter mode
RUSTFLAGS_8BIT:=$(RUSTFLAGS_BASE)
RUSTFLAGS_8BIT+=-Cllvm-args=-sanitizer-coverage-inline-8bit-counters

# PC guard mode
RUSTFLAGS_PCGUARD:=$(RUSTFLAGS_BASE)
RUSTFLAGS_PCGUARD+=-Cllvm-args=-sanitizer-coverage-trace-pc-guard

# Honggfuzz mode: PC guards with all trace features
# https://github.com/rust-fuzz/honggfuzz-rs/blob/master/src/bin/cargo-hfuzz.rs
# Note: indirect-calls is enabled via level=4 in RUSTFLAGS_BASE
RUSTFLAGS_HFUZZ:=$(RUSTFLAGS_PCGUARD)
RUSTFLAGS_HFUZZ+=-Cllvm-args=-sanitizer-coverage-trace-compares
RUSTFLAGS_HFUZZ+=-Cllvm-args=-sanitizer-coverage-trace-divs
RUSTFLAGS_HFUZZ+=-Cllvm-args=-sanitizer-coverage-trace-geps
RUSTFLAGS_HFUZZ+=-Cllvm-args=-sanitizer-coverage-stack-depth

RUSTFLAGS:=$(RUSTFLAGS_8BIT)

ifeq ($(ENABLE_COVERAGE),1)
RUSTFLAGS+=-Cinstrument-coverage
$(info "Coverage enabled")
endif

CC:=clang

CARGO?=cargo

.PHONY: build clean binaries shared_obj shared_obj_hfuzz shared_obj_pcguard

all: | shared_obj binaries

# Alias for backwards compatibility
build: | shared_obj

conformance: | shared_obj_debug

shared_obj:
	RUSTFLAGS="$(RUSTFLAGS)" $(CARGO) build --target x86_64-unknown-linux-gnu --release --lib

shared_obj_hfuzz:
	RUSTFLAGS="$(RUSTFLAGS_HFUZZ)" $(CARGO) build --target x86_64-unknown-linux-gnu --profile release-with-debug --lib --target-dir target/hfuzz

shared_obj_pcguard:
	RUSTFLAGS="$(RUSTFLAGS_PCGUARD)" $(CARGO) build --target x86_64-unknown-linux-gnu --release --lib --target-dir target/pcguard

shared_obj_cov:
	RUSTFLAGS="$(RUSTFLAGS) -Cinstrument-coverage" $(CARGO) build --target x86_64-unknown-linux-gnu --release \
	 --lib --target-dir target/cov

	# to avoid conflicts when uploading as GH artifact
	cp target/cov/x86_64-unknown-linux-gnu/release/libsolfuzz_agave.so target/x86_64-unknown-linux-gnu/release/libsolfuzz_agave+cov.so

shared_obj_debug:
	$(CARGO) build --lib

shared_obj_core_bpf:
	./scripts/fetch_program.sh $(PROGRAM)
	CARGO=$(CARGO) ./scripts/build_core_bpf.sh $(PROGRAM)

shared_obj_bpf_conformance:
	RUSTFLAGS="$(RUSTFLAGS)" BPF_PROGRAM_ID=$(BPF_PROGRAM_ID) BPF_TARGET=$(BPF_TARGET) FORCE_RECOMPILE=true $(CARGO) build \
		--target x86_64-unknown-linux-gnu \
		--features bpf-program-conformance \
		--lib \
		--release \
		--target-dir target/bpf-conformance
	mv target/bpf-conformance/x86_64-unknown-linux-gnu/release/libsolfuzz_agave.so target/bpf-conformance/$(OUTPUT_TARGET_NAME)

shared_obj_bpf_conformance_debug:
	BPF_PROGRAM_ID=$(BPF_PROGRAM_ID) BPF_TARGET=$(BPF_TARGET) FORCE_RECOMPILE=true $(CARGO) build \
                --target x86_64-unknown-linux-gnu \
                --features bpf-program-conformance \
                --lib \
                --target-dir target/bpf-conformance
	mv target/bpf-conformance/x86_64-unknown-linux-gnu/debug/libsolfuzz_agave.so target/bpf-conformance/$(OUTPUT_TARGET_NAME)

binaries:
	$(CARGO) build --bins --release

tests/self_test: tests/self_test.c
	$(CC) -o $@ $< -Werror=all -pedantic -ldl -fsanitize=address,fuzzer-no-link -fsanitize-coverage=inline-8bit-counters

test:
	$(CARGO) check --release
	$(CARGO) test --release

clean:
	$(CARGO) clean
