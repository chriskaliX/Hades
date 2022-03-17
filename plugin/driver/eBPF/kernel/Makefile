# tools
CMD_TR ?= tr
CMD_CUT ?= cut
CMD_LLC ?= llc
CMD_CLANG ?= clang-12 # this may be changed to clang, it's fine
CMD_LLVM_STRIP ?= llvm-strip

# pre-check tool exists
EXECUTABLES = $(CMD_TR) $(CMD_CUT) $(CMD_LLC) $(CMD_CLANG) $(CMD_LLVM_STRIP)
CHECK_TOOLS_EXSITS := $(foreach exec,$(EXECUTABLES),\
        $(if $(shell command -v $(exec) 2> /dev/null), ,then $(error "No $(exec) in PATH")) )

# pre-check tool version
CLANG_VERSION := $(shell $(CMD_CLANG) --version 2>/dev/null | \
	head -1 | $(CMD_TR) -d '[:alpha:]' | $(CMD_TR) -d '[:space:]' | $(CMD_CUT) -d'.' -f1)

# envs
KERN_RELEASE ?= $(shell uname -r)
ARCH_UNAME := $(shell uname -m)
ARCH ?= $(ARCH_UNAME:aarch64=arm64)
linux_arch := $(ARCH:x86_64=x86)
KERN_SRC_PATH := /usr/src/linux-headers-$(KERN_RELEASE)
KERN_BLD_PATH := /usr/lib/modules/$(KERN_RELEASE)/build
BPF_HEADERS := headers
INCLUDE_PATH := include

# colors
INFO_COLOR = \033[34m[*]\033[0m
SUCC_COLOR = \033[32m[+]\033[0m
FAIL_COLOR = \033[31m[-]\033[0m

all:
	@echo "| ---------------------------- |"
	@echo "|   \033[35mHades\033[0m eBPF Kernel Driver   |"
	@echo "|    based on Tracee/Elkeid    |"
	@echo "|         @chriskaliX          |"
	@echo "| ---------------------------- |"

	@printf "$(INFO_COLOR) Start to build hades_ebpf_driver\n"

	@printf "$(INFO_COLOR) Pre-check for compile tools exists\n"
	$(CHECK_TOOLS_EXSITS)
	@printf "$(SUCC_COLOR) Tools all exist\n"

	@printf "$(INFO_COLOR) Pre-check for clang version\n"
	@if [ $(CLANG_VERSION) -lt 12 ]; \
		then echo "$(FAIL_COLOR) clang mininum version 12 is required" && exit 1;\
	fi;
	@printf "$(SUCC_COLOR) Clang version pass\n"

	# linux-headers check here

	@printf "$(INFO_COLOR) Clean for the old driver...\n"
	$(MAKE) clean -s --no-print-directory
	@printf "$(INFO_COLOR) Compile driver\n"
	$(MAKE) hades_ebpf_driver.o -s --no-print-directory
	$(shell cp hades_ebpf_driver.o ../userspace/hades_ebpf_driver.o)

hades_ebpf_driver.o: src/hades.c
	$(CMD_CLANG) src/hades.c -S \
		-D__BPF_TRACING__ \
		-D__KERNEL__ \
		-D__TARGET_ARCH_$(linux_arch) \
		-include $(KERN_SRC_PATH)/include/linux/kconfig.h \
		-I $(KERN_SRC_PATH)/arch/$(linux_arch)/include \
		-I $(KERN_SRC_PATH)/arch/$(linux_arch)/include/uapi \
		-I $(KERN_BLD_PATH)/arch/$(linux_arch)/include/generated \
		-I $(KERN_BLD_PATH)/arch/$(linux_arch)/include/generated/uapi \
		-I $(KERN_SRC_PATH)/include \
		-I $(KERN_BLD_PATH)/include \
		-I $(KERN_SRC_PATH)/include/uapi \
		-I $(KERN_BLD_PATH)/include/generated \
		-I $(KERN_BLD_PATH)/include/generated/uapi \
		-I $(BPF_HEADERS) \
		-I $(INCLUDE_PATH) \
		-Wunused \
		-Wall \
		-Wno-frame-address \
		-Wno-unused-value \
		-Wno-unknown-warning-option \
		-Wno-pragma-once-outside-header \
		-Wno-pointer-sign \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-deprecated-declarations \
		-Wno-compare-distinct-pointer-types \
		-Wno-address-of-packed-member \
		-fno-stack-protector \
		-fno-jump-tables \
		-fno-unwind-tables \
		-fno-asynchronous-unwind-tables \
		-xc \
		-nostdinc \
		-O2 -emit-llvm -c -g -o $(@:.o=.ll)
	$(CMD_LLC) -march=bpf -filetype=obj -o $@ $(@:.o=.ll)
	rm $(@:.o=.ll)

clean:
	rm -f hades_ebpf_driver.o