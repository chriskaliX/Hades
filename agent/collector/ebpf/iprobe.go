package ebpf

// cfc4n/ehids, 学习一下
// type IBPFProbe interface {
// 	// Init 初始化
// 	Init(context.Context) error

// 	// GetProbeBytes  获取当前加载器的probebytes
// 	GetProbeBytes() []byte

// 	// ProbeName 获取当前probe的名字
// 	ProbeName() string

// 	// ProbeObjects ProbeObjects设置
// 	// ProbeObjects() IClose

// 	// LoadToKernel load bpf字节码到内核
// 	LoadToKernel() error

// 	// AttachProbe hook到对应probe
// 	AttachProbe() error

// 	// Run 事件监听感知
// 	Run() error

// 	// Reader
// 	// Reader() []IClose

// 	//OutPut 输出上报
// 	//OutPut() bool

// 	// Decode 解码，输出或发送到消息队列等
// 	Decode(*ebpf.Map, []byte) (string, error)

// 	// Close 关闭退出
// 	Close() error
// }

// type EBPFProbe struct {
// 	probeBytes []byte
// 	opts       *ebpf.CollectionOptions
// 	// probeObjects IEBPFProbeObject
// 	// reader       []IClose
// 	ctx   context.Context
// 	child IBPFProbe

// 	// probe的名字
// 	name string

// 	// probe的类型，uprobe,kprobe等
// 	probeType string
// }

// func (e *EBPFProbe) Init(ctx context.Context) error {
// 	e.ctx = ctx
// 	return nil
// }

// func (e *EBPFProbe) LoadToKernel() error {
// 	reader := bytes.NewReader(e.probeBytes)
// 	// 从 elf 中 load, 不走原先的 bpf2cmd
// 	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
// 	if err != nil {
// 		return fmt.Errorf("can't load Probe: %w, eBPF bytes length:%d", err, len(e.probeBytes))
// 	}

// 	err = spec.LoadAndAssign(e.probeObjects, e.opts)
// 	if err != nil {
// 		return err
// 	}
// 	e.reader = append(e.reader, e.probeObjects)
// 	return nil
// }
