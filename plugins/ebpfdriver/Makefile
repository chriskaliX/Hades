EBPF_BUILD := +$(MAKE) -C kern
EBPF_CO-RE_FLAG := core
EBPF_SOURCE_PATH = kern/hades_ebpf_driver.bpf.o
EBPF_SOURCE_CO-RE_PATH = kern/hades_ebpf_driver.bpf.core.o
EBPF_TARGET_PATH = user/hades_ebpf_driver.o
GO_TARGET_PATH := -o ebpfdriver
VERSION := v1.1.0

no-core:
	$(EBPF_BUILD)
	mv $(EBPF_SOURCE_PATH) $(EBPF_TARGET_PATH)
	CGO_ENABLED=0 go build -ldflags "-X 'hades-ebpf/conf.VERSION=$(VERSION)'" $(GO_TARGET_PATH) .
core:
	$(EBPF_BUILD) $(EBPF_CO-RE_FLAG)
	mv $(EBPF_SOURCE_CO-RE_PATH) $(EBPF_TARGET_PATH)
	CGO_ENABLED=0 go build -ldflags "-X 'hades-ebpf/conf.VERSION=$(VERSION)'" $(GO_TARGET_PATH) .
testing:
	cp $(EBPF_TARGET_PATH) test/hades_ebpf_driver.o
	CGO_ENABLED=0 go test -v -exec sudo ./...