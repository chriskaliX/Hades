CMD_NFPM ?= nfpm
EXECUTABLES = $(CMD_NFPM)

CHECK_TOOLS_EXSITS := $(foreach exec,$(EXECUTABLES),\
        $(if $(shell command -v $(exec) 2> /dev/null), ,then $(error "No $(exec) in PATH")) )

# colors
INFO_COLOR = \033[34m[*]\033[0m
SUCC_COLOR = \033[32m[+]\033[0m
FAIL_COLOR = \033[31m[-]\033[0m
HIGHLIGHT_COLOR = \033[35mHades\033[0m

.PHONY: pre_show
pre_show:
	@echo   "┌──────────────────────────────┐"
	@printf "│      $(HIGHLIGHT_COLOR) Agent Packing     │\n"
	@echo   "│    based on Tracee/Elkeid    │"
	@echo   "│         @chriskaliX          │"
	@echo   "└──────────────────────────────┘"
	@printf "$(INFO_COLOR) Pre-check for compile tools exists\n"
	$(CHECK_TOOLS_EXSITS)
	@printf "$(SUCC_COLOR) Tools all exist\n"

deb: \
	pre_show
	@printf "$(INFO_COLOR) packing for DEB\n"
	nfpm pkg --packager deb --target /tmp/

rpm: \
	pre_show
	@printf "$(INFO_COLOR) packing for RPM\n"
	nfpm pkg --packager rpm --target /tmp/
