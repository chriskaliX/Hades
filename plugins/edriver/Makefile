# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
# Extra cargo features appended to every --features= flag.
# Set to ",vendored-libelf" on glibc hosts (ubuntu CI) where the system
# libelf.a is glibc-compiled and vendored compilation is required.
CARGO_EXTRA_FEATURES ?=

PLATFORM := $(shell uname -m)
LIBC     ?= musl

build:
	cargo fmt
	cargo build --release --bin edriver --target $(PLATFORM)-unknown-linux-$(LIBC) --features=static$(CARGO_EXTRA_FEATURES)

debug:
	cargo fmt
	cargo build --release --bin edriver --target $(PLATFORM)-unknown-linux-$(LIBC) --features=static,debug$(CARGO_EXTRA_FEATURES)

test:
	cargo fmt
	cargo test --target $(PLATFORM)-unknown-linux-$(LIBC) --features=static,debug$(CARGO_EXTRA_FEATURES) -- --include-ignored --show-output
