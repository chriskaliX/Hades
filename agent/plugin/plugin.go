package plugin

import (
	"agent/agent"
	"agent/core/pool"
	"agent/proto"
	"agent/utils"
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"go.uber.org/zap"
)

type Plugin struct {
	config proto.Config
	mu     sync.Mutex // according to uber_go_guide, pointer of mutex is not needed
	cmd    *exec.Cmd
	// rx/tx, all from the agent perspective
	rx      io.ReadCloser
	rxBytes uint64
	rxCnt   uint64
	tx      io.WriteCloser
	txBytes uint64
	txCnt   uint64

	updateTime time.Time
	reader     *bufio.Reader
	taskCh     chan proto.Task
	done       chan struct{} // same with the context done
	wg         *sync.WaitGroup
	workdir    string
	// SugaredLogger/Logger
	logger *zap.SugaredLogger
}

// @TODO: StartProcess
func NewPlugin(ctx context.Context, config proto.Config) (p *Plugin, err error) {
	var (
		rx_r, rx_w, tx_r, tx_w *os.File
		errFile                *os.File
	)
	p = &Plugin{
		config:     config,
		updateTime: time.Now(),
		done:       make(chan struct{}),
		taskCh:     make(chan proto.Task),
		wg:         &sync.WaitGroup{},
		logger:     zap.S().With("plugin", config.Name, "pver", config.Version, "psign", config.Signature),
	}
	p.workdir = path.Join(agent.DefaultAgent.Workdir(), "plugin", p.Name())
	// pipe init
	// In Elkeid, a note: 'for compatibility' is here. Since some systems only allow
	// half-duplex pipe.
	rx_r, rx_w, err = os.Pipe()
	if err != nil {
		p.logger.Error("rx pipe init")
		return
	}
	p.rx = rx_r
	tx_r, tx_w, err = os.Pipe()
	if err != nil {
		p.logger.Error("tx pipe init")
		return
	}
	p.tx = tx_w
	// reader init
	p.reader = bufio.NewReaderSize(rx_r, 1024*128)
	// purge the files
	os.Remove(path.Join(p.workdir, p.Name()+".stderr"))
	os.Remove(path.Join(p.workdir, p.Name()+".stdout"))
	// cmdline
	execPath := path.Join(p.workdir, p.Name())
	err = utils.CheckSignature(execPath, config.Signature)
	if err != nil {
		p.logger.Warn("check signature failed")
		p.logger.Info("start download")
		err = utils.Download(ctx, execPath, config.Sha256, config.DownloadUrls, config.Type)
		if err != nil {
			p.logger.Error("download failed:", err)
			return
		}
		p.logger.Info("download success")
	}
	cmd := exec.Command(execPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.ExtraFiles = append(cmd.ExtraFiles, tx_r, rx_w)
	cmd.Dir = p.workdir
	if errFile, err = os.OpenFile(execPath+".stderr", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o0600); err != nil {
		p.logger.Error("open stderr:", errFile)
		return
	}
	defer errFile.Close()
	cmd.Stderr = errFile
	if config.Detail != "" {
		cmd.Env = append(cmd.Env, "DETAIL="+config.Detail)
	}
	p.logger.Info("cmd start")
	err = cmd.Start()
	if err != nil {
		p.logger.Error("cmd start:", err)
	}
	rx_w.Close()
	tx_r.Close()
	p.cmd = cmd
	return
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

// TODO:shutdown for plugin, need to change...
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
		rec *proto.EncodedRecord
		err error
	)
	defer p.wg.Done()
	for {
		if rec, err = p.receiveData(); err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				// problem of multi
				p.logger.Warn("buffer full, skip")
				continue
				// any error about close or EOF, it's done
			} else if !(errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, os.ErrClosed)) {
				p.logger.Error("receive err:", err)
				// add continue to any error
				continue
			} else {
				p.logger.Error("exit the receive task:", err)
				break
			}
		}
		// TODO: upload via `Logger Plugin` here, not to the service..
		fmt.Println(string(rec.Data))
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

// receive data, not added
func (p *Plugin) receiveData() (rec *proto.EncodedRecord, err error) {
	var l uint32
	err = binary.Read(p.reader, binary.LittleEndian, &l)
	if err != nil {
		return
	}
	_, err = p.reader.Discard(1)
	if err != nil {
		return
	}
	te := 1

	rec = pool.Get()
	var dt, ts, e int

	dt, e, err = readVarint(p.reader)
	if err != nil {
		return
	}
	_, err = p.reader.Discard(1)
	if err != nil {
		return
	}
	te += e + 1
	rec.DataType = int32(dt)

	ts, e, err = readVarint(p.reader)
	if err != nil {
		return
	}
	_, err = p.reader.Discard(1)
	if err != nil {
		return
	}
	te += e + 1
	rec.Timestamp = int64(ts)

	if uint32(te) < l {
		_, e, err = readVarint(p.reader)
		if err != nil {
			return
		}
		te += e
		ne := int(l) - te
		if cap(rec.Data) < ne {
			rec.Data = make([]byte, ne)
		} else {
			rec.Data = rec.Data[:ne]
		}
		_, err = io.ReadFull(p.reader, rec.Data)
		if err != nil {
			return
		}
	}
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

// @TODO: go through this
func readVarint(r io.ByteReader) (int, int, error) {
	varint := 0
	eaten := 0
	for shift := uint(0); ; shift += 7 {
		if shift >= 64 {
			return 0, eaten, proto.ErrIntOverflowGrpc
		}
		b, err := r.ReadByte()
		if err != nil {
			return 0, eaten, err
		}
		eaten++
		varint |= int(b&0x7F) << shift
		if b < 0x80 {
			break
		}
	}
	return varint, eaten, nil
}
