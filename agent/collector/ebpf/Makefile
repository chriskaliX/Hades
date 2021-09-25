TARGET := ebpf
TARGET_BPF := $(TARGET).bpf.o
BPF_SRC = $(shell find . -type f -name '*.c')
.PHONY: all
all: $(TARGET) $(TARGET_BPF)

$(TARGET_BPF): $(BPF_SRC)
	clang -I /usr/include/ -O2 -c -target bpf -o $@ $<