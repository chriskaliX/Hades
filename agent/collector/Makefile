build:
	go generate
	llvm-strip ./kprobeexample_bpfeb.o --no-strip-all -R .BTF
	llvm-strip ./kprobeexample_bpfel.o --no-strip-all -R .BTF