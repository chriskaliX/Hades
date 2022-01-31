package plugin

import (
	"agent/agent"
	"agent/proto"
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
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
	logger     *log.Logger

	workdir string
}

func NewPlugin(config proto.Config) (p *Plugin, err error) {
	p = &Plugin{}
	p.config = config
	// set workdir
	p.workdir = path.Join(agent.WorkingDirectory, "plugin", p.Name())
	// pipe init
	// In Elkeid, a note: 'for compatibility' is here.  Since some systems only allow
	// half-duplex pipe.
	var rx_r, rx_w, tx_r, tx_w *os.File
	rx_r, rx_w, err = os.Pipe()
	if err != nil {
		return
	}
	rx_w.Close()
	p.rx = rx_r
	tx_r, tx_w, err = os.Pipe()
	if err != nil {
		return
	}
	tx_r.Close()
	p.tx = tx_w
	// reader init
	p.reader = bufio.NewReaderSize(rx_r, 1024*128)

	p.updateTime = time.Now()
	p.done = make(chan struct{})
	p.taskCh = make(chan proto.Task)
	p.wg = &sync.WaitGroup{}
	// purge the files
	os.Remove(path.Join(p.workdir, p.Name()+".stderr"))
	os.Remove(path.Join(p.workdir, p.Name()+".stdout"))
	return
}

func (p *Plugin) SetCmd(cmd *exec.Cmd) {
	p.cmd = cmd
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
func (p *Plugin) IsExited() bool { return p.cmd.ProcessState.Exited() }

// TODO:shutdown for plugin, need to change...
func (p *Plugin) Shutdown() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.IsExited() {
		return
	}
	p.tx.Close()
	p.rx.Close()
	select {
	case <-time.After(time.Second * 30):
		syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
		<-p.done
	case <-p.done:
	}
}

func (p *Plugin) Receive() {
	defer p.wg.Done()
	for {
		rec, err := p.receiveData()
		if err != nil {
			// TODO: log here
		} else if !(errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, os.ErrClosed)) {
			// TODO: log here
		} else {
			break
		}
		fmt.Println(rec)
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
				continue
			}
			binary.LittleEndian.PutUint32(dst[:4], uint32(s))
			var n int
			n, err = p.tx.Write(dst)
			if err != nil {
				if !errors.Is(err, os.ErrClosed) {
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
	// test code
	testSlice := make([]byte, 0, 100)
	_, err = io.ReadFull(p.reader, testSlice)
	fmt.Println(string(testSlice))
	atomic.AddUint64(&p.rxCnt, 1)
	return
}

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
