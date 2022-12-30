package SDK

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/chriskaliX/SDK/clock"
	"github.com/chriskaliX/SDK/config"
	"github.com/chriskaliX/SDK/logger"
	"github.com/chriskaliX/SDK/transport/client"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/nightlyone/lockfile"
	"go.uber.org/zap"
)

var _ ISandbox = (*Sandbox)(nil)

type ISandbox interface {
	// Sandbox action
	Init(sconfig *SandboxConfig) error
	Run(func(ISandbox) error) error
	Shutdown()
	// Sandbox attributes and context
	Name() string
	Context() context.Context
	Cancel()
	// Client related
	SendRecord(*protocol.Record) error
	SetSendHook(client.SendHookFunction)
	// TaskReceiver
	RecvTask() *protocol.Task
}

// Sandbox is the abstract behavior interfaces for every plugin
type Sandbox struct {
	// required fields
	Clock  clock.IClock
	Logger *zap.Logger
	Client *client.Client
	name   string
	// context
	ctx    context.Context
	cancel context.CancelFunc
	// others
	sigs   chan os.Signal
	debug  bool
	taskCh chan *protocol.Task
}

type SandboxConfig struct {
	Debug     bool
	Name      string
	LogConfig *logger.Config
}

func NewSandbox() *Sandbox {
	return &Sandbox{}
}

func (s *Sandbox) Init(sconfig *SandboxConfig) error {
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.sigs = make(chan os.Signal, 1)
	s.name = sconfig.Name
	s.debug = sconfig.Debug
	s.taskCh = make(chan *protocol.Task)
	// Required fields initialization
	s.Clock = clock.New(100 * time.Millisecond)
	s.Client = client.New(s.Clock)
	sconfig.LogConfig.Clock = s.Clock
	sconfig.LogConfig.Client = s.Client
	s.Logger = logger.New(sconfig.LogConfig)
	defer s.Logger.Info(fmt.Sprintf("sandbox %s init", s.name))
	// Environment setting
	if !s.Client.IsHooked() && s.Debug() {
		s.Client.SetSendHook(s.Client.SendDebug)
	}
	// Task receiving
	go s.recvTask()
	return nil
}

// Run a main function, just a wrapper
func (s *Sandbox) Run(mfunc func(ISandbox) error) (err error) {
	defer s.Logger.Info(fmt.Sprintf("%s is exited", s.name))
	s.Logger.Info(fmt.Sprintf("%s run is called", s.name))
	if err = mfunc(s); err != nil {
		zap.S().Error("sandbox main func failed, %s", err.Error())
		return err
	}
	s.Logger.Info(fmt.Sprintf("%s is running", s.name))
	// os.Interrupt for command line
	signal.Notify(s.sigs, syscall.SIGTERM, syscall.SIGTERM, os.Interrupt)
	for {
		select {
		case sig := <-s.sigs:
			s.Logger.Info(fmt.Sprintf("signal %s received, %s will exit after 3 seconds", sig.String(), s.Name()))
			s.cancel()
			<-time.After(3 * time.Second)
			if s.debug {
				return
			}
		case <-s.ctx.Done():
			if s.debug {
				time.Sleep(5 * time.Second)
				continue
			}
			s.Logger.Info(fmt.Sprintf("cancel received, %s will exit after 5 seconds", s.Name()))
			<-time.After(5 * time.Second)
			return nil
		default:
			time.Sleep(time.Second)
		}
	}
}

func (s *Sandbox) Shutdown() {
	s.Logger.Info(fmt.Sprintf("%s calls shutdown", s.Name()))
	s.cancel()
	s.Clock.Close()
	<-time.After(1 * time.Second)
}

func (s *Sandbox) Name() string {
	return s.name
}

func (s *Sandbox) Debug() bool {
	return s.debug
}

// Is this too strict, this also works in windows, since pgid is
func (s *Sandbox) SendRecord(rec *protocol.Record) (err error) {
	err = s.Client.SendRecord(rec)
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return
		} else if !(errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, os.ErrClosed)) {
			return
		} else {
			s.Shutdown()
		}
	}
	return
}

func (s *Sandbox) Context() context.Context {
	return s.ctx
}

func (s *Sandbox) Cancel() {
	s.cancel()
}

func (s *Sandbox) SetSendHook(hook client.SendHookFunction) {
	s.Client.SetSendHook(hook)
}

// check pid file if it's not debug
// also, we should remove this in Shutdown
func (s *Sandbox) Lockfile() error {
	var dir string
	if s.debug {
		return nil
	}
	if runtime.GOOS == "linux" {
		dir = "/var/lock/hades/"
	} else if runtime.GOOS == "windows" {
		dir = "\\Program Files\\hades\\"
	}

	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			if err = os.Mkdir(dir, os.ModePerm); err != nil {
				return err
			}
		} else {
			return err
		}
	}
	l, _ := lockfile.New(dir + s.name + ".lockfile")
	if err := l.TryLock(); err != nil {
		return err
	}
	return nil
}

func (s *Sandbox) RecvTask() *protocol.Task {
	return <-s.taskCh
}

func (s *Sandbox) recvTask() {
	if s.debug {
		return
	}
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
			task, err := s.Client.ReceiveTask()
			if err != nil {
				s.Logger.Error(err.Error())
				time.Sleep(5 * time.Second)
				continue
			}
			// Hook the shutdown here
			if task.DataType == config.TaskShutdown {
				s.Logger.Info("task shutdown received")
				s.Shutdown()
			}
			s.taskCh <- task
		}
	}
}
