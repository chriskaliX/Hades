all:
	cd kernel && make && cd ../
	mv kernel/hades_ebpf_driver.o userspace/hades_ebpf_driver.o
	go build .
	mv hades-ebpf ../driver
debug:
	cd kernel && make && cd ../
	mv kernel/hades_ebpf_driver.o userspace/hades_ebpf_driver.o
	go build -ldflags="-X hades-ebpf/userspace.Env=debug" .
	mv hades-ebpf ../driver