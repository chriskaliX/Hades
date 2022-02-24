panic: runtime error: slice bounds out of range [:4294967295] with capacity 1024

goroutine 26 [running]:
collector/ebpf/userspace/parser.getStr({0x788d80, 0xc00084e480}, 0xffffffff)
	/root/Hades/plugin/collector/ebpf/userspace/parser/common.go:24 +0x19f
collector/ebpf/userspace/parser.ParseStr({0x788d80, 0xc00084e480})
	/root/Hades/plugin/collector/ebpf/userspace/parser/common.go:43 +0xe5
collector/ebpf/userspace/parser.Execve({0x788d80, 0xc00084e480}, 0xc000614800)
	/root/Hades/plugin/collector/ebpf/userspace/parser/execve.go:23 +0x186
collector/ebpf.(*HadesObject).Read(0xc0002a0d20)
	/root/Hades/plugin/collector/ebpf/hades.go:169 +0x8bb
collector/ebpf.(*EBPFProbe).Run(0xc0000b3f60)
	/root/Hades/plugin/collector/ebpf/iprobe.go:70 +0xaf
collector/ebpf.Hades()
	/root/Hades/plugin/collector/ebpf/ebpf.go:26 +0x25a
created by main.main
	/root/Hades/plugin/collector/main.go:38 +0x1d5