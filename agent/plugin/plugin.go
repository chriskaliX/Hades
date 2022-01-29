package plugin

import (
	"agent/proto"
	"bufio"
	"errors"
	"io"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

var (
	pluginsMap = &sync.Map{}
	// sync channel for plugin
	syncCh = make(chan map[string]*proto.Config, 1)
)

// this is same with the meituan's article. To make the action of
// plugins is abstract.

func Get(name string) (*Plugin, bool) {
	plg, ok := pluginsMap.Load(name)
	if ok {
		return plg.(*Plugin), ok
	}
	return nil, ok
}

func GetAll() (plgs []*Plugin) {
	pluginsMap.Range(func(key, value interface{}) bool {
		plg := value.(*Plugin)
		plgs = append(plgs, plg)
		return true
	})
	return
}

func Sync(cfgs map[string]*proto.Config) (err error) {
	select {
	case syncCh <- cfgs:
	default:
		err = errors.New("plugins are syncing or context has been cancled")
	}
	return
}

type Plugin struct {
	Config proto.Config
	mu     *sync.Mutex
	cmd    *exec.Cmd
	// 从agent视角看待的rx tx
	rx         io.ReadCloser
	updateTime time.Time
	reader     *bufio.Reader
	tx         io.WriteCloser
	taskCh     chan proto.Task
	done       chan struct{}
	wg         *sync.WaitGroup
	// 与上面的rx tx概念相反 是从plugin视角看待的
	rxBytes uint64
	txBytes uint64
	rxCnt   uint64
	txCnt   uint64
	// zap not added
}

func (p *Plugin) GetState() (RxSpeed, TxSpeed, RxTPS, TxTPS float64) {
	now := time.Now()
	instant := now.Sub(p.updateTime).Seconds()
	if instant != 0 {
		RxSpeed = float64(atomic.SwapUint64(&p.rxBytes, 0)) / float64(instant)
		TxSpeed = float64(atomic.SwapUint64(&p.txBytes, 0)) / float64(instant)
		RxTPS = float64(atomic.SwapUint64(&p.rxCnt, 0)) / float64(instant)
		TxTPS = float64(atomic.SwapUint64(&p.txCnt, 0)) / float64(instant)
	}
	p.updateTime = now
	return
}
func (p *Plugin) Name() string {
	return p.Config.Name
}
func (p *Plugin) Version() string { return p.Config.Version }
func (p *Plugin) Pid() int {
	return p.cmd.Process.Pid
}

// get the state by fork status
func (p *Plugin) IsExited() bool {
	return p.cmd.ProcessState != nil
}

// receive data, not added

func (p *Plugin) SendTask(task proto.Task) (err error) {
	select {
	case p.taskCh <- task:
	default:
		err = errors.New("plugin is processing task or context has been cancled")
	}
	return
}

func (p *Plugin) GetWorkingDirectory() string {
	return p.cmd.Dir
}
