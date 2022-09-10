package SDK

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/chriskaliX/SDK/clock"
	"github.com/chriskaliX/SDK/logger"
	"github.com/chriskaliX/SDK/transport/client"
	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/chriskaliX/SDK/util/hash"
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
	// Hash Wrapper
	GetHash(string) string
}

// Sandbox is the abstract behavior interfaces for every plugin
type Sandbox struct {
	// required fields
	Clock  clock.IClock
	Logger logger.ILogger
	Client *client.Client
	name   string
	// Optional fields
	Hash hash.IHashCache
	// context
	ctx    context.Context
	cancel context.CancelFunc
	// others
	sigs  chan os.Signal
	debug bool
	Task  chan *protocol.Task
}

type SandboxConfig struct {
	Debug     bool
	Hash      bool
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
	s.Task = make(chan *protocol.Task)
	// Required fields initialization
	s.Clock = clock.New(time.Second)
	s.Client = client.New(s.Clock)
	sconfig.LogConfig.Clock = s.Clock
	sconfig.LogConfig.Client = s.Client
	s.Logger = logger.New(sconfig.LogConfig)
	// lockfile for plugin
	if err := s.Lockfile(); err != nil {
		zap.S().Errorf("init failed with lockfile %s", err.Error())
		return err
	}
	defer s.Logger.Info(fmt.Sprintf("sandbox %s init", s.name))
	// Optional fields initialization
	if sconfig.Hash {
		s.Hash = hash.NewWithClock(s.Clock)
	}
	// Environment setting
	if s.Debug() {
		s.Client.SetSendHook(s.Client.SendDebug)
	}
	// Sandbox internal cron job
	go s.ReceiveTask()
	return nil
}

// Run a main function, just a wrapper
func (s *Sandbox) Run(mfunc func(ISandbox) error) (err error) {
	defer s.Logger.Info(fmt.Sprintf("%s is exited", s.name))
	s.Logger.Info(fmt.Sprintf("%s Run calls", s.name))
	if err = mfunc(s); err != nil {
		return err
	}
	s.Logger.Info(fmt.Sprintf("%s is running", s.name))
	// os.Interrupt for command line
	signal.Notify(s.sigs, syscall.SIGTERM, os.Interrupt)
	for {
		select {
		case sig := <-s.sigs:
			s.Logger.Info(fmt.Sprintf("signal %s received, %s will exit after 5 seconds", sig.String(), s.Name()))
			s.cancel()
			<-time.After(5 * time.Second)
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
}

func (s *Sandbox) Name() string {
	return s.name
}

func (s *Sandbox) Debug() bool {
	return s.debug
}

func (s *Sandbox) SendRecord(rec *protocol.Record) error {
	return s.Client.SendRecord(rec)
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

func (s *Sandbox) GetHash(path string) string {
	return s.Hash.GetHash(path)
}

// check pid file if it's not debug
func (s *Sandbox) Lockfile() error {
	if s.debug {
		return nil
	}
	// TODO: Windows?
	if runtime.GOOS == "linux" {
		// dir check
		dir := "/var/lock/hades/"
		_, err := os.Stat(dir)
		if err != nil {
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
	}
	return nil
}

// Unfinished: task resolve
func (s *Sandbox) ReceiveTask() {
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
				s.Logger.Error(err)
				time.Sleep(5 * time.Second)
				continue
			}
			s.Task <- task
		}
	}
}
