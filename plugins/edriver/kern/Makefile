# Precheck for tools and their versions.
CMD_TR ?= tr
CMD_CUT ?= cut
CMD_LLC ?= llc
CMD_CLANG ?= clang
OPT ?= opt
LLVM_DIS ?= llvm-dis
CMD_LLVM_STRIP ?= llvm-strip
EXECUTABLES = $(CMD_TR) $(CMD_CUT) $(CMD_LLC) $(CMD_CLANG) $(CMD_LLVM_STRIP)
CHECK_TOOLS_EXSITS := $(foreach exec,$(EXECUTABLES),\
        $(if $(shell command -v $(exec) 2> /dev/null), ,then $(error "No $(exec) in PATH")) )
CLANG_VERSION := $(shell $(CMD_CLANG) --version 2>/dev/null | \
	head -1 | $(CMD_TR) -d '[:alpha:]' | $(CMD_TR) -d '[:space:]' | $(CMD_CUT) -d'.' -f1)

# envs
KERN_RELEASE ?= $(shell uname -r)
ARCH_UNAME := $(shell uname -m)
ARCH ?= $(ARCH_UNAME:aarch64=arm64)
linux_arch := $(ARCH:x86_64=x86)
# some different with tracee. Need to check for this
KERN_BLD_PATH := $(if $(KERN_HEADERS),$(KERN_HEADERS),/lib/modules/$(KERN_RELEASE)/build)
KERN_SRC_PATH := $(if $(KERN_HEADERS),$(KERN_HEADERS),$(if $(wildcard /lib/modules/$(KERN_RELEASE)/source),/lib/modules/$(KERN_RELEASE)/source,$(KERN_BLD_PATH)))

BPF_HEADERS := headers
INCLUDE_PATH := include
LIB_PATH := ../../libs
HADES_SRC := src/hades.c

# colors
INFO_COLOR = \033[34m[*]\033[0m
SUCC_COLOR = \033[32m[+]\033[0m
FAIL_COLOR = \033[31m[-]\033[0m
HIGHLIGHT_COLOR = \033[35mHades\033[0m

nocore: \
	pre_show
	@printf "$(INFO_COLOR) Compile driver from kernel headers\n"
	$(MAKE) hades_ebpf_driver.bpf.o -s --no-print-directory

core: \
	pre_show
	@printf "$(INFO_COLOR) Compile CO-RE driver\n"
	$(MAKE) bpf-core -s --no-print-directory

.PHONY: pre_show
pre_show:
	@echo   "┌──────────────────────────────┐"
	@printf "│   $(HIGHLIGHT_COLOR) eBPF Kernel Driver   │\n"
	@echo   "│    based on Tracee/Elkeid    │"
	@echo   "│         @chriskaliX          │"
	@echo   "└──────────────────────────────┘"
	@printf "$(INFO_COLOR) Start to build hades_ebpf_driver\n"
	@printf "$(INFO_COLOR) Pre-check for compile tools exists\n"
	$(CHECK_TOOLS_EXSITS)
	@printf "$(SUCC_COLOR) Tools all exist\n"
	@printf "$(INFO_COLOR) Pre-check for clang version\n"
	@if [ $(CLANG_VERSION) -lt 12 ]; \
		then echo "$(FAIL_COLOR) clang mininum version 12 is required" && exit 1;\
	fi;
	@printf "$(SUCC_COLOR) Clang version pass\n"
	@printf "$(INFO_COLOR) Clean for the old driver...\n"
	$(MAKE) clean -s --no-print-directory

# libbpf
# Build libbpf to get the common headers for both core and no-core
# some helpers, defs and macros
LIBBPF_CFLAGS = "-fPIC"
LIBBPF_LDLAGS =
LIBBPF_SRC = $(LIB_PATH)/libbpf/src
headers/libbpf/libbpf.a: \
	$(LIBBPF_SRC) \
	$(wildcard $(LIBBPF_SRC)/*.[ch]) \

	CC="$(CMD_CLANG)" \
		CFLAGS="$(LIBBPF_CFLAGS)" \
		LD_FLAGS="$(LIBBPF_LDFLAGS)" \
		$(MAKE) \
		-C $(LIBBPF_SRC) \
		BUILD_STATIC_ONLY=1 \
		DESTDIR=$(abspath ./headers/libbpf/) \
		OBJDIR=$(abspath ./headers/libbpf/obj) \
		INCLUDEDIR= LIBDIR= UAPIDIR= prefix= libdir= \
		install install_uapi_headers
	install -m 0640 ./headers/libbpf/bpf/*.h ./headers/

# NOT CO-RE
# KBUILD_NAME: https://github.com/iovisor/bpftrace/pull/1352
hades_ebpf_driver.bpf.o: \
	headers/libbpf/libbpf.a \
	$(HADES_SRC)

	$(CMD_CLANG) -S \
		-D__BPF_TRACING__ \
		-D__KERNEL__ \
		-D__TARGET_ARCH_$(linux_arch) \
		-DKBUILD_MODNAME=\"hades\" \
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
		-I $(BPF_HEADERS)/libbpf \
		-I $(BPF_HEADERS) \
		-I $(INCLUDE_PATH) \
		-I $(LIB_PATH)/bpfheaders/ \
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
		-c $(HADES_SRC) \
		-O2 -emit-llvm -c -g -o $(@:.o=.ll)
	$(CMD_LLC) -march=bpf -filetype=obj -o $@ $(@:.o=.ll)
	rm $(@:.o=.ll)

# CO-RE
# Since CO-RE needs the BTF embeded on the kernel. Portable can only be archieved in
# some lastest kernel version. But, thanks to libbpf and btfhub, we can make bpf prog
# CO-RE in lower kernel version since external raw BTF files is supported in libbpf
# and here is the commit:
# https://github.com/libbpf/libbpf/commit/4920031c8809696debf43f7b0c8f95ea24b8f61c
# It's a great idea and it's been done is Tracee v0.7.0
# But still, BTFhub is used for portable. Distribution like CentOS 7 based on kernel
# version 3.x get very limited eBPF features. For the HIDS programs like Tracee or 
# Hades, it would be limited by eBPF features and it's nothing to do with CO-RE.
# Again, we need to know that the mininum kernel version of Hades is 4.18.
# And we use BTFhub to support CO-RE in some distribution that NOT support BTF.
# BTFhub helps us to backport CO-RE in some kernel versions.
.PHONY: bpf-core
bpf-core: hades_ebpf_driver.bpf.core.o
hades_ebpf_driver.bpf.core.o: \
	$(HADES_SRC) \
	headers/libbpf/libbpf.a

	$(CMD_CLANG) \
		-D__TARGET_ARCH_$(linux_arch) \
		-D__BPF_TRACING__ \
		-DCORE \
		-I $(BPF_HEADERS)/libbpf \
		-I $(BPF_HEADERS) \
		-I $(INCLUDE_PATH) \
		-I $(LIB_PATH)/core/ \
		-I $(LIB_PATH)/bpfheaders/ \
		-target bpf \
		-O2 -g \
		-march=bpf -mcpu=v2 \
		-c $(HADES_SRC) \
		-o $@

.PHONY:clean
clean:
	rm -f hades_ebpf_driver.bpf.o
	rm -f hades_ebpf_driver.bpf.core.o
