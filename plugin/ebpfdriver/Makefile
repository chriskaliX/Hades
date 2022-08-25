EBPF_BUILD := +$(MAKE) -C kern
EBPF_CO-RE_FLAG := core
EBPF_SOURCE_PATH = kern/hades_ebpf_driver.bpf.o
EBPF_SOURCE_CO-RE_PATH = kern/hades_ebpf_driver.bpf.core.o
EBPF_TARGET_PATH = user/hades_ebpf_driver.o
GO_TARGET_PATH := -o ebpfdriver

no-core:
	$(EBPF_BUILD)
	mv $(EBPF_SOURCE_PATH) $(EBPF_TARGET_PATH)
	go build $(GO_TARGET_PATH) .
core:
	$(EBPF_BUILD) $(EBPF_CO-RE_FLAG)
	mv $(EBPF_SOURCE_CO-RE_PATH) $(EBPF_TARGET_PATH)
	go build $(GO_TARGET_PATH) .