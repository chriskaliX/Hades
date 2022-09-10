package server

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chriskaliX/SDK/transport/pool"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/chriskaliX/SDK/util"
	"go.uber.org/zap"
)

// Server-side data-structure of SDK plugin, proto.Config is
// deprecated since we only focus on itself.
type Server struct {
	config     Config
	mu         sync.Mutex
	cmd        *exec.Cmd
	rx         io.ReadCloser // Read
	rxBytes    uint64
	rxCnt      uint64
	tx         io.WriteCloser // Write
	txBytes    uint64
	txCnt      uint64
	updateTime time.Time
	reader     *bufio.Reader
	taskCh     chan protocol.Task
	done       chan struct{}
	wg         *sync.WaitGroup
	workdir    string
	logger     *zap.SugaredLogger
}

// NewServer does all things, except download/check/run the exec file
func NewServer(ctx context.Context, workdir string, conf interface{}) (s *Server, err error) {
	var rx_r, rx_w, tx_r, tx_w, errFile *os.File
	// internal config parser
	config, err := parseConfig(conf)
	if err != nil {
		return
	}
	// Server init
	s = &Server{
		config:     config,
		updateTime: time.Now(),
		done:       make(chan struct{}),
		taskCh:     make(chan protocol.Task),
		wg:         &sync.WaitGroup{},
		logger:     zap.S().With("plugin", config.Name, "pver", config.Version, "psign", config.Signature),
	}
	s.workdir = filepath.Join(workdir, "plugin", s.Name())
	// pipe init
	rx_r, rx_w, err = os.Pipe()
	if err != nil {
		s.logger.Error("rx pipe init")
		return
	}
	s.rx = rx_r
	defer rx_w.Close()
	tx_r, tx_w, err = os.Pipe()
	if err != nil {
		s.logger.Error("tx pipe init")
		return
	}
	s.tx = tx_w
	defer tx_r.Close()
	s.reader = bufio.NewReaderSize(rx_r, 1024*128)
	os.Remove(filepath.Join(s.workdir, s.Name()+".stderr"))
	os.Remove(filepath.Join(s.workdir, s.Name()+".stdout"))
	// cmdline
	execPath := filepath.Join(s.workdir, s.Name())
	err = util.CheckSignature(execPath, config.Signature)
	if err != nil {
		s.logger.Warn("check signature failed")
		s.logger.Info("start download")
		err = util.Download(ctx, execPath, config.Sha256, config.DownloadUrls, config.Type)
		if err != nil {
			s.logger.Error("download failed:", err)
			return
		}
		s.logger.Info("download success")
	}
	// cmdline init
	cmd := exec.CommandContext(ctx, execPath)
	cmd.ExtraFiles = append(cmd.ExtraFiles, tx_r, rx_w)
	cmd.Dir = s.workdir
	s.cmd = cmd
	s.cmdInit()
	if errFile, err = os.OpenFile(execPath+".stderr", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o0600); err != nil {
		s.logger.Error("open stderr:", errFile)
		return
	}
	defer errFile.Close()
	cmd.Stderr = errFile
	// details. if it is needed
	if config.Detail != "" {
		cmd.Env = append(cmd.Env, "DETAIL="+config.Detail)
	}
	s.logger.Info("cmd start")
	err = cmd.Start()
	if err != nil {
		s.logger.Error("cmd start:", err)
	}
	return
}

// Wait till we exit
func (s *Server) Wait() (err error) {
	defer s.wg.Done()
	err = s.cmd.Wait()
	s.rx.Close()
	s.tx.Close()
	close(s.done)
	return
}

func (s *Server) GetState() (RxSpeed, TxSpeed, RxTPS, TxTPS float64) {
	now := time.Now()
	instant := now.Sub(s.updateTime).Seconds()
	if instant != 0 {
		RxSpeed = float64(atomic.SwapUint64(&s.rxBytes, 0)) / float64(instant)
		TxSpeed = float64(atomic.SwapUint64(&s.txBytes, 0)) / float64(instant)
		RxTPS = float64(atomic.SwapUint64(&s.rxCnt, 0)) / float64(instant)
		TxTPS = float64(atomic.SwapUint64(&s.txCnt, 0)) / float64(instant)
	}
	s.updateTime = now
	return
}

func (s *Server) Receive(poolGet protocol.PoolGet, trans protocol.Trans) {
	var err error
	defer s.wg.Done()
	for {
		rec := poolGet()
		if err = s.receive(rec); err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				// problem of multi
				s.Logger().Warn("buffer full, skip")
				continue
			} else if !(errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, os.ErrClosed)) {
				s.Logger().Error("receive err:", err)
				continue
			} else {
				s.Logger().Error("exit the receive task:", err)
				break
			}
		}
		trans.TransmissionSDK(rec, false)
	}
}

// An internal Receive, better for
func (s *Server) receive(rec protocol.ProtoType) (err error) {
	var l uint32
	err = binary.Read(s.reader, binary.LittleEndian, &l)
	if err != nil {
		return
	}
	// issues: https://github.com/golang/go/issues/23199
	// solutions:
	// https://github.com/golang/go/blob/7e394a2/src/net/http/h2_bundle.go#L998-L1043
	// For ebpfdriver, most of the length within 1024, so I assume that
	// a buffer pool with 1 << 10 & 1 << 12 will meet the requirements.
	// Any buffer larger than 4096 should be ignored and let the GC
	// dealing with this issue.
	message := pool.BufferPool.Get(int64(l))
	defer pool.BufferPool.Put(message)
	if _, err = io.ReadFull(s.reader, message); err != nil {
		return
	}
	if err = rec.Unmarshal(message); err != nil {
		return
	}
	// Incr for plugin status
	atomic.AddUint64(&s.txCnt, 1)
	atomic.AddUint64(&s.txBytes, uint64(l))
	return
}

func (s *Server) SendTask(task protocol.Task) (err error) {
	select {
	case s.taskCh <- task:
	default:
		err = errors.New("plugin is processing task or context has been canceled")
	}
	return
}

func (s *Server) Name() string { return s.config.Name }

func (s *Server) Version() string { return s.config.Version }

func (s *Server) Pid() int { return s.cmd.Process.Pid }

func (s *Server) IsExited() bool { return s.cmd.ProcessState.Exited() }

func (s *Server) GetWorkingDirectory() string { return s.cmd.Dir }

func (s *Server) Wg() *sync.WaitGroup { return s.wg }

func (s *Server) Logger() *zap.SugaredLogger { return s.logger }

// background task resolve
func (s *Server) Task() (err error) {
	defer s.wg.Done()
	for {
		select {
		case <-s.done:
			return
		case task := <-s.taskCh:
			size := task.Size()
			var dst = make([]byte, 4+size)
			_, err = task.MarshalToSizedBuffer(dst[4:])
			if err != nil {
				s.logger.Errorf("task: %+v, err: %v", task, err)
				continue
			}
			binary.LittleEndian.PutUint32(dst[:4], uint32(size))
			var n int
			n, err = s.tx.Write(dst)
			if err != nil {
				if !errors.Is(err, os.ErrClosed) {
					s.logger.Error("when sending task, an error occurred: ", err)
				}
				return
			}
			atomic.AddUint64(&s.txCnt, 1)
			atomic.AddUint64(&s.txBytes, uint64(n))
		}
	}
}
