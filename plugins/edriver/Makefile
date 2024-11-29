EBPF_BUILD := +$(MAKE) -C bpf
EBPF_CO-RE_FLAG := core
EBPF_SOURCE_PATH = bpf/hades_ebpf_driver.bpf.o
EBPF_SOURCE_CO-RE_PATH = bpf/hades_ebpf_driver.bpf.core.o
EBPF_TARGET_PATH = pkg/hades_ebpf_driver.o
GO_TARGET_PATH := -o edriver
VERSION := v1.1.2

.PHONY: mod-tidy
mod-tidy:
	@echo "Running go mod tidy..."
	go mod tidy

no-core: mod-tidy
	$(EBPF_BUILD)
	mv $(EBPF_SOURCE_PATH) $(EBPF_TARGET_PATH)
	CGO_ENABLED=0 go build -ldflags "-X 'edriver/constants.VERSION=$(VERSION)'" $(GO_TARGET_PATH) .
core: mod-tidy
	$(EBPF_BUILD) $(EBPF_CO-RE_FLAG)
	mv $(EBPF_SOURCE_CO-RE_PATH) $(EBPF_TARGET_PATH)
	CGO_ENABLED=0 go build -ldflags "-X 'edriver/constants.VERSION=$(VERSION)'" $(GO_TARGET_PATH) .
testing: mod-tidy
	cp $(EBPF_TARGET_PATH) tests/hades_ebpf_driver.o
	CGO_ENABLED=0 go test -v -exec sudo ./...