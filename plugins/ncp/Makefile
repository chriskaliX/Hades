CMD_GO ?= go
VERSION ?= v1.0.0

# colors
INFO_COLOR = \033[34m[*]\033[0m
SUCC_COLOR = \033[32m[+]\033[0m
FAIL_COLOR = \033[31m[-]\033[0m

all: pre_show build_ncp

.PHONY: pre_show
pre_show:
	@printf "$(INFO_COLOR) start to build ncp, version: $(VERSION)\n"

.PHONY: build_ncp
build_ncp:
	$(CMD_GO) build -o ncp