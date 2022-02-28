package userspace

// Object 需要实现的
type IBPFProbeObject interface {
	// 挂载 Hook 点
	AttachProbe() error
	// 读取 Hook 点, 逻辑写在 Read 里
	Read() error
	// 关闭 Hook 点(关闭 reader, 再关闭 Linker)
	Close() error
}
