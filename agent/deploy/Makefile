# colors
INFO_COLOR = \033[34m[*]\033[0m
SUCC_COLOR = \033[32m[+]\033[0m
FAIL_COLOR = \033[31m[!]\033[0m
HIGHLIGHT_COLOR = \033[35mHades\033[0m

# Packaging tools (pure Rust, install once):
#   cargo install cargo-deb
#   cargo install cargo-generate-rpm
WORKSPACE_ROOT := $(abspath ..)

.PHONY: pre_show
pre_show:
	@echo   "┌──────────────────────────────┐"
	@printf "│      $(HIGHLIGHT_COLOR) Agent Packing     │\n"
	@echo   "│    based on Tracee/Elkeid    │"
	@echo   "│         @chriskaliX          │"
	@echo   "└──────────────────────────────┘"
	@printf "$(FAIL_COLOR) NOTICE - CHECK BEFORE DEPLOY IN PROD\n"
	@echo   "    arch    : host arch (override with CARGO_BUILD_TARGET)"
	@echo   "    version : defined in ../Cargo.toml [package].version"
	@echo   "    CA      : check the certification if TLS is enabled"
	@echo   "    address : hardcode in src/transport/connection.rs -> 127.0.0.1 by default"
	@printf "$(INFO_COLOR) example: make deb  or  make rpm\n"

# Build all workspace members in release mode (hades-agent + hadesctl).
# Both binaries end up in ../target/release/ because they share a workspace.
#
# Override the default gRPC address at compile time:
#   GRPC_ADDR=https://your-server:8000 make deb
.PHONY: release
release:
	@printf "$(INFO_COLOR) building workspace (release)\n"
	cargo build --release --workspace --manifest-path $(WORKSPACE_ROOT)/Cargo.toml
	@printf "$(SUCC_COLOR) release build done\n"

# cargo-deb reads [package.metadata.deb] from ../Cargo.toml.
# --no-build skips a second build; `make release` must have run first.
.PHONY: deb
deb: pre_show release
	@printf "$(INFO_COLOR) packing .deb (cargo-deb)\n"
	cargo deb --no-build --manifest-path $(WORKSPACE_ROOT)/Cargo.toml --output /tmp/
	@printf "$(SUCC_COLOR) .deb created in /tmp/\n"

# cargo-generate-rpm reads [package.metadata.generate-rpm] from ../Cargo.toml.
# Lifecycle scripts are passed at build time via --set-metadata because
# cargo-generate-rpm expects script *content*, not file paths.
.PHONY: rpm
rpm: pre_show release
	@printf "$(INFO_COLOR) packing .rpm (cargo-generate-rpm)\n"
	cargo generate-rpm \
	  --manifest-path $(WORKSPACE_ROOT)/Cargo.toml \
	  --output /tmp/
	@printf "$(SUCC_COLOR) .rpm created in /tmp/\n"

.PHONY: clean
clean:
	cargo clean --manifest-path $(WORKSPACE_ROOT)/Cargo.toml

