CMD_NFPM ?= nfpm
EXECUTABLES = $(CMD_NFPM)

CHECK_TOOLS_EXSITS := $(foreach exec,$(EXECUTABLES),\
        $(if $(shell command -v $(exec) 2> /dev/null), ,then $(error "No $(exec) in PATH")) )

# colors
INFO_COLOR = \033[34m[*]\033[0m
SUCC_COLOR = \033[32m[+]\033[0m
FAIL_COLOR = \033[31m[!]\033[0m
HIGHLIGHT_COLOR = \033[35mHades\033[0m

.PHONY: pre_show
pre_show:
	@echo   "┌──────────────────────────────┐"
	@printf "│      $(HIGHLIGHT_COLOR) Agent Packing     │\n"
	@echo   "│    based on Tracee/Elkeid    │"
	@echo   "│         @chriskaliX          │"
	@echo   "└──────────────────────────────┘"
	@printf "$(FAIL_COLOR) NOTICE - CHECK BEFORE DEPLOY IN PROD\n"
	@echo   "    arch    : defined in nfpm.yaml"
	@echo   "    version : defined in nfpm.yaml"
	@echo   "    CA      : check the certification if TLS is enabled"
	@echo   "    address : hardcode in agent/main.go, grpc.hades.store -> 127.0.0.1 by default"
	@echo   "              the domain is owned by chriskaliX, change dns resolve if you need"
	@printf "$(INFO_COLOR) example: make deb(rpm)\n"

.PHONY: tool_check
tool_check:
	@printf "$(INFO_COLOR) pre check for compile tools exists\n"
	$(CHECK_TOOLS_EXSITS)
	@printf "$(SUCC_COLOR) tools check done\n"

.PHONY: build_hades_agent
build_hades_agent:
	make -C ../
	mv ../hades-agent ./
	@printf "$(SUCC_COLOR) hades-agent build success\n"

.PHONY: build_hadesctl
build_hadesctl:
	@printf "$(INFO_COLOR) start to build hadesctl\n"
	cd control/ && CGO_ENABLED=0 go build . && cd ..
	mv control/hadesctl hadesctl
	@printf "$(SUCC_COLOR) hadesctl build success\n"

deb: \
	pre_show tool_check build_hades_agent build_hadesctl
	@printf "$(INFO_COLOR) packing for DEB\n"
	nfpm pkg --packager deb --target /tmp/

rpm: \
	pre_show tool_check build_hades_agent build_hadesctl
	@printf "$(INFO_COLOR) packing for RPM\n"
	nfpm pkg --packager rpm --target /tmp/
