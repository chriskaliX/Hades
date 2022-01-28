build:
	go generate
	llvm-strip ./sysexecve_bpfeb.o --no-strip-all -R .BTF
	llvm-strip ./sysexecve_bpfel.o --no-strip-all -R .BTF
	llvm-strip ./sockets_bpfel.o --no-strip-all -R .BTF
	llvm-strip ./sockets_bpfeb.o --no-strip-all -R .BTF