BUILD_VERSION ?= $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*= *"\(.*\)"/\1/')

# colors
INFO_COLOR = \033[34m[*]\033[0m
SUCC_COLOR = \033[32m[+]\033[0m
FAIL_COLOR = \033[31m[-]\033[0m

all: build

.PHONY: build
build:
	@printf "$(INFO_COLOR) building hades-agent (debug), version: $(BUILD_VERSION)\n"
	cargo build

.PHONY: release
release:
	@printf "$(INFO_COLOR) building hades-agent (release), version: $(BUILD_VERSION)\n"
	cargo build --release
	@printf "$(SUCC_COLOR) build complete: target/release/hades-agent\n"

.PHONY: check
check:
	cargo check

.PHONY: test
test:
	cargo test

.PHONY: clean
clean:
	cargo clean

# deploy/Makefile runs `cargo build --release` for the whole workspace itself,
# so no separate `release` prerequisite is needed here.
.PHONY: deb
deb:
	make -C deploy/ deb

.PHONY: rpm
rpm:
	make -C deploy/ rpm

