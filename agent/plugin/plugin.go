package plugin

import (
	"agent/agent"
	"agent/proto"
	"agent/transport"
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"
)

var (
	errDupPlugin = errors.New("duplicate plugin load")
)

func Load(ctx context.Context, config proto.Config) (err error) {
	loadedPlg, ok := DefaultManager.Get(config.GetName())
	// logical problem
	if ok {
		if loadedPlg.Version() == config.GetVersion() && !loadedPlg.IsExited() {
			return errDupPlugin
		}
		if loadedPlg.Version() != config.GetVersion() && !loadedPlg.IsExited() {
			loadedPlg.Shutdown()
		}
	}
	if config.GetSignature() == "" {
		config.Signature = config.GetSha256()
	}
	plg, err := NewPlugin(ctx, config)
	if err != nil {
		return
	}
	plg.wg.Add(3)
	go plg.Wait()
	go plg.Receive()
	go plg.Task()
	DefaultManager.Register(plg.Name(), plg)
	return nil
}

func Startup(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			DefaultManager.UnregisterAll()
			return
		case cfgs := <-DefaultManager.syncCh:
			// 加载插件
			for _, cfg := range cfgs {
				if cfg.Name != agent.Product {
					err := Load(ctx, *cfg)
					// 相同版本的同名插件正在运行，无需操作
					if err == errDupPlugin {
						continue
					}
					if err != nil {
						zap.S().Error(err)
					} else {
						zap.S().Info("plugin has been loaded")
					}
				}
			}
			// 移除插件
			for _, plg := range DefaultManager.GetAll() {
				if _, ok := cfgs[plg.Name()]; !ok {
					plg.Shutdown()
					DefaultManager.UnRegister(plg.Name())
					if err := os.RemoveAll(plg.GetWorkingDirectory()); err != nil {
						zap.S().Error(err)
					}
				}
			}
		}
	}
}

type Plugin struct {
	config     proto.Config
	mu         sync.Mutex
	cmd        *exec.Cmd
	rx         io.ReadCloser
	rxBytes    uint64
	rxCnt      uint64
	tx         io.WriteCloser
	txBytes    uint64
	txCnt      uint64
	updateTime time.Time
	reader     *bufio.Reader
	taskCh     chan proto.Task
	done       chan struct{} // same with the context done
	wg         *sync.WaitGroup
	workdir    string
	logger     *zap.SugaredLogger
}

func (p *Plugin) Wait() (err error) {
	defer p.wg.Done()
	err = p.cmd.Wait()
	p.rx.Close()
	p.tx.Close()
	close(p.done)
	return
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

func (p *Plugin) Name() string { return p.config.Name }

func (p *Plugin) Version() string { return p.config.Version }

func (p *Plugin) Pid() int { return p.cmd.Process.Pid }

// get the state by fork status
func (p *Plugin) IsExited() bool { return p.cmd.ProcessState != nil }

func (p *Plugin) Shutdown() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.IsExited() {
		return
	}
	p.logger.Info("shutdown called")
	p.tx.Close()
	p.rx.Close()
	select {
	case <-time.After(time.Second * 30):
		p.logger.Warn("close by killing start")
		syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
		<-p.done
		p.logger.Info("close by killing done")
	case <-p.done:
		p.logger.Info("close by done channel")
	}
}

func (p *Plugin) Receive() {
	var (
		rec *proto.Record
		err error
	)
	defer p.wg.Done()
	for {
		if rec, err = p.receiveDataWithSize(); err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				// problem of multi
				p.logger.Warn("buffer full, skip")
				continue
				// any error about close or EOF, it's done
			} else if !(errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, os.ErrClosed)) {
				p.logger.Error("receive err:", err)
				continue
			} else {
				p.logger.Error("exit the receive task:", err)
				break
			}
		}
		// fmt.Println(rec)
		transport.DTransfer.Transmission(rec, false)
	}
}

func (p *Plugin) Task() {
	var err error
	defer p.wg.Done()
	for {
		select {
		case <-p.done:
			return
		case task := <-p.taskCh:
			s := task.Size()
			var dst = make([]byte, 4+s)
			_, err = task.MarshalToSizedBuffer(dst[4:])
			if err != nil {
				p.logger.Errorf("task: %+v, err: %v", task, err)
				continue
			}
			binary.LittleEndian.PutUint32(dst[:4], uint32(s))
			var n int
			n, err = p.tx.Write(dst)
			if err != nil {
				if !errors.Is(err, os.ErrClosed) {
					p.logger.Error("when sending task, an error occurred: ", err)
				}
				return
			}
			atomic.AddUint64(&p.txCnt, 1)
			atomic.AddUint64(&p.txBytes, uint64(n))
		}
	}
}

// In Elkeid, receiveData get the data by decoding the data by self-code
// which performs better. For now, we work in an native way.
func (p *Plugin) receiveDataWithSize() (rec *proto.Record, err error) {
	var l uint32
	err = binary.Read(p.reader, binary.LittleEndian, &l)
	if err != nil {
		return
	}
	// TODO: sync.Pool\
	// TODO: sync.Pool, discard by cap
	rec = &proto.Record{}
	// issues: https://github.com/golang/go/issues/23199
	// solutions: https://github.com/golang/go/blob/7e394a2/src/net/http/h2_bundle.go#L998-L1043
	message := make([]byte, int(l))
	if _, err = io.ReadFull(p.reader, message); err != nil {
		return
	}
	if err = rec.Unmarshal(message); err != nil {
		return
	}
	// Incr for plugin status
	atomic.AddUint64(&p.txCnt, 1)
	atomic.AddUint64(&p.txBytes, uint64(l))
	return
}

func (p *Plugin) SendTask(task proto.Task) (err error) {
	select {
	case p.taskCh <- task:
	default:
		err = errors.New("plugin is processing task or context has been canceled")
	}
	return
}

func (p *Plugin) GetWorkingDirectory() string {
	return p.cmd.Dir
}

func init() {
	go func() {
		for {
			select {
			case task := <-transport.PluginTaskChan:
				// In future, shutdown, update, restart will be in here
				if plg, ok := DefaultManager.Get(task.GetObjectName()); ok {
					if err := plg.SendTask(*task); err != nil {
						zap.S().Error("send task to plugin: ", err)
					}
				} else {
					zap.S().Error("can't find plugin: ", task.GetObjectName())
				}
			case cfgs := <-transport.PluginConfigChan:
				if err := DefaultManager.Sync(cfgs); err != nil {
					zap.S().Error("config sync failed: ", err)
				}
			}
		}
	}()
}
