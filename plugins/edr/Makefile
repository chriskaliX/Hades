EBPF_BUILD := +$(MAKE) -C kern
NAME := hades_edr
EBPF_CO-RE_FLAG := core
EBPF_SOURCE_PATH = kern/$(NAME).bpf.o
EBPF_SOURCE_CO-RE_PATH = kern/$(NAME).core.bpf.o
EBPF_TARGET_PATH = $(NAME).bpf.o
GO_TARGET_PATH := -o edr
VERSION := v1.0.0

no-core:
	$(EBPF_BUILD)
	mv $(EBPF_SOURCE_PATH) $(EBPF_TARGET_PATH)
	go build -ldflags "-X 'edr/pkg/conf.VERSION=$(VERSION)'" $(GO_TARGET_PATH) .
core:
	$(EBPF_BUILD) $(EBPF_CO-RE_FLAG)
	mv $(EBPF_SOURCE_CO-RE_PATH) $(EBPF_TARGET_PATH)
	go build -ldflags "-X 'edr/pkg/conf.VERSION=$(VERSION)'" $(GO_TARGET_PATH) .
testing:
	cp $(EBPF_TARGET_PATH) test/$(EBPF_TARGET_PATH)
	go test -v -exec sudo ./...