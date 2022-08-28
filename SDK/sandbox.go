package SDK

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/chriskaliX/SDK/clock"
	"github.com/chriskaliX/SDK/logger"
	"github.com/chriskaliX/SDK/transport"
	"github.com/chriskaliX/SDK/util/hash"
)

var _ ISandbox = (*Sandbox)(nil)

type ISandbox interface {
	// Sandbox action
	Init(sconfig *SandboxConfig)
	Run(func(ISandbox) error) error
	Shutdown()
	// Sandbox attributes and context
	Name() string
	Context() context.Context
	Cancel()
	// Client related
	SendRecord(*transport.Record) error
	SetSendHook(transport.SendHookFunction)
	// Hash Wrapper
	GetHash(string) string
}

// Sandbox is the abstract behavior interfaces for every plugin
type Sandbox struct {
	// required fields
	Clock  clock.IClock
	Logger logger.ILogger
	Client *transport.Client
	name   string
	// Optional fields
	Hash hash.IHashCache
	// context
	ctx    context.Context
	cancel context.CancelFunc
	// others
	sigs  chan os.Signal
	debug bool
	Task  chan *transport.Task
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

func (s *Sandbox) Init(sconfig *SandboxConfig) {
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.sigs = make(chan os.Signal, 1)
	// Required fields initialization
	s.Clock = clock.New(time.Second)
	s.Client = transport.New(s.Clock)
	sconfig.LogConfig.Clock = s.Clock
	sconfig.LogConfig.Client = s.Client
	s.Logger = logger.New(sconfig.LogConfig)
	s.name = sconfig.Name
	s.debug = sconfig.Debug
	s.Task = make(chan *transport.Task)
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

func (s *Sandbox) SendRecord(rec *transport.Record) error {
	return s.Client.SendRecord(rec)
}

func (s *Sandbox) Context() context.Context {
	return s.ctx
}

func (s *Sandbox) Cancel() {
	s.cancel()
}

func (s *Sandbox) SetSendHook(hook transport.SendHookFunction) {
	s.Client.SetSendHook(hook)
}

func (s *Sandbox) GetHash(path string) string {
	return s.Hash.GetHash(path)
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
