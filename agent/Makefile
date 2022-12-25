CMD_GO ?= go
VERSION ?= v1.0.2

# colors
INFO_COLOR = \033[34m[*]\033[0m
SUCC_COLOR = \033[32m[+]\033[0m
FAIL_COLOR = \033[31m[-]\033[0m

all: pre_show build_agent

.PHONY: pre_show
pre_show:
	@printf "$(INFO_COLOR) start to build hades-agent, version: $(VERSION)\n"

.PHONY: build_agent
build_agent:
	$(CMD_GO) build -ldflags "-X agent/agent.Version=$(VERSION)" -o hades-agent