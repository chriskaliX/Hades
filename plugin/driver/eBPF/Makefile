all:
	cd kernel && make && cd ../
	mv kernel/hades_ebpf_driver.o userspace/hades_ebpf_driver.o
	go build .
	mv hades-ebpf ../driver