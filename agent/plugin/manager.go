package plugin

import (
	"agent/agent"
	"agent/proto"
	"agent/transport/pool"
	"context"
	"errors"
	"fmt"
	"os"
	"sync"

	"agent/transport"

	SDK "github.com/chriskaliX/SDK/transport"
	"github.com/chriskaliX/SDK/transport/server"
)

var DefaultManager = &Manager{
	plugins: &sync.Map{},
	syncCh:  make(chan map[string]*proto.Config, 1),
}

// move to struct, dependency injection
type Manager struct {
	plugins *sync.Map
	syncCh  chan map[string]*proto.Config
}

// Get plugin's server side interface
func (m *Manager) Get(name string) (SDK.IServer, bool) {
	if plg, ok := m.plugins.Load(name); ok {
		return plg.(SDK.IServer), ok
	}
	return nil, false
}

// GetAll returns all plugin interfaces
func (m *Manager) GetAll() (plgs []SDK.IServer) {
	m.plugins.Range(func(_, value any) bool {
		plg := value.(SDK.IServer)
		plgs = append(plgs, plg)
		return true
	})
	return
}

// Load plugin from proto.Config which has already checked
// in Download and CheckSignature function, the real plugin
// and server has already packaged into SDK
func (m *Manager) Load(ctx context.Context, cfg proto.Config) (err error) {
	if plg, ok := m.Get(cfg.Name); ok && !plg.IsExited() {
		if plg.Version() == cfg.Version {
			return nil
		}
		plg.Shutdown()
	}
	if cfg.Signature == "" {
		cfg.Signature = cfg.Sha256
	}
	plg, err := server.NewServer(ctx, agent.Workdir, &cfg)
	if err != nil {
		agent.SetAbnormal(fmt.Sprintf("plugin % starts failed: %s", cfg.Name, err))
		return
	}
	plg.Wg().Add(3)
	go plg.Wait()
	go plg.Receive(pool.SDKGet, transport.DefaultTrans)
	go plg.Task()
	m.Register(plg.Name(), plg)
	return nil
}

func (m *Manager) Sync(cfgs map[string]*proto.Config) (err error) {
	select {
	case m.syncCh <- cfgs:
	default:
		err = errors.New("plugins are syncing or context has been cancled")
	}
	return
}

func (m *Manager) Register(name string, plg SDK.IServer) {
	m.plugins.Store(name, plg)
}

func (m *Manager) UnRegister(name string) (err error) {
	plg, ok := m.Get(name)
	if !ok {
		err = fmt.Errorf("%s is not available", name)
		return
	}
	plg.Shutdown()
	m.plugins.Delete(name)
	if err = os.RemoveAll(plg.GetWorkingDirectory()); err != nil {
		agent.SetAbnormal(fmt.Sprintf("%s remove work dir failed: %s", name, err.Error()))
		return
	}
	return
}

func (m *Manager) UnregisterAll() {
	subWg := &sync.WaitGroup{}
	m.plugins.Range(func(_, value any) bool {
		subWg.Add(1)
		plg := value.(SDK.IServer)
		go func() {
			defer subWg.Done()
			plg.Shutdown()
			plg.Wg().Wait()
			m.plugins.Delete(plg.Name())
		}()
		return true
	})
	subWg.Wait()
}
