CMD_GO ?= go
VERSION ?= 1.0.1

all: build_agent

.PHONY: build_agent
build_agent:
	$(CMD_GO) build -ldflags "-X agent/agent.Version='$(VERSION)'" -o hades-agent