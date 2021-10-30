build:
	go generate
	llvm-strip ./bpf_bpfeb.o --no-strip-all -R .BTF
	llvm-strip ./bpf_bpfel.o --no-strip-all -R .BTF