pwd = $(shell pwd)

build:
	clang -I /usr/include/ \
	-I $(pwd)/headers/ \
	-c ebpf.c \
	-o ebpf.o