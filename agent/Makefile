BUILD_VERSION ?= $(shell grep '^version' Cargo.toml | head -1 | sed 's/.*= *"\(.*\)"/\1/')
TARGET       ?= x86_64-unknown-linux-musl
USE_CROSS    ?= 0
BUILD_CMD     = $(if $(filter 1,$(USE_CROSS)),cross,cargo)

# CC + linker for native x86_64 musl (ignored when USE_CROSS=1).
# Setting both mirrors Elkeid RASP practice: CC_xxx covers any C deps (cc-rs),
# CARGO_TARGET_xxx_LINKER covers the Rust link step.
export CC_x86_64_unknown_linux_musl              ?= musl-gcc
export CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER ?= musl-gcc

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

# Fully static musl binary — works on any Linux regardless of glibc version.
# Usage:
#   make release-musl                          # x86_64 (default)
#   make release-musl TARGET=aarch64-unknown-linux-musl USE_CROSS=1
.PHONY: release-musl
release-musl:
	@printf "$(INFO_COLOR) building hades-agent (musl static) target=$(TARGET), version: $(BUILD_VERSION)\n"
	$(BUILD_CMD) build --release --workspace --target $(TARGET)
	@printf "$(SUCC_COLOR) build complete: target/$(TARGET)/release/hades-agent\n"

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

# Package both .deb and .rpm from a single musl build.
# Usage:
#   make package-musl
#   make package-musl TARGET=aarch64-unknown-linux-musl USE_CROSS=1
.PHONY: package-musl
package-musl: release-musl
	cargo deb --no-build --target $(TARGET) --output /tmp/
	cargo generate-rpm --target $(TARGET) \
	  --set-metadata 'pre_install_script="$(shell cat deploy/scripts/preinst)"' \
	  --set-metadata 'post_install_script="$(shell cat deploy/scripts/postinst)"' \
	  --set-metadata 'pre_uninstall_script="$(shell cat deploy/scripts/prerm)"' \
	  --set-metadata 'post_uninstall_script="$(shell cat deploy/scripts/postrm)"' \
	  --output /tmp/
	@printf "$(SUCC_COLOR) .deb and .rpm packaged to /tmp/\n"

# Package a musl-static .deb.
# Usage:
#   make deb-musl                              # x86_64
#   make deb-musl TARGET=aarch64-unknown-linux-musl USE_CROSS=1
.PHONY: deb-musl
deb-musl: release-musl
	cargo deb --no-build --target $(TARGET) --output /tmp/
	@printf "$(SUCC_COLOR) deb packaged to /tmp/\n"

.PHONY: rpm
rpm:
	make -C deploy/ rpm

# Package a musl-static .rpm.
# Usage:
#   make rpm-musl                              # x86_64
#   make rpm-musl TARGET=aarch64-unknown-linux-musl USE_CROSS=1
.PHONY: rpm-musl
rpm-musl: release-musl
	cargo generate-rpm --target $(TARGET) \
	  --set-metadata 'pre_install_script="$(shell cat deploy/scripts/preinst)"' \
	  --set-metadata 'post_install_script="$(shell cat deploy/scripts/postinst)"' \
	  --set-metadata 'pre_uninstall_script="$(shell cat deploy/scripts/prerm)"' \
	  --set-metadata 'post_uninstall_script="$(shell cat deploy/scripts/postrm)"' \
	  --output /tmp/
	@printf "$(SUCC_COLOR) rpm packaged to /tmp/\n"

