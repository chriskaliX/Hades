# tools
CMD_LLC ?= llc
CMD_CLANG ?= clang-12
CMD_LLVM_STRIP ?= llvm-strip

# envs
KERN_RELEASE ?= $(shell uname -r)
ARCH_UNAME := $(shell uname -m)
ARCH ?= $(ARCH_UNAME:aarch64=arm64)
linux_arch := $(ARCH:x86_64=x86)
KERN_SRC_PATH := /usr/src/linux-headers-$(KERN_RELEASE)
KERN_BLD_PATH := /usr/lib/modules/$(KERN_RELEASE)/build
BPF_HEADERS := ../headers

tracer.o: tracer.c
	$(CMD_CLANG) tracer.c -S \
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
	-$(CMD_LLVM_STRIP) $@ --no-strip-all -R .BTF
	rm $(@:.o=.ll)