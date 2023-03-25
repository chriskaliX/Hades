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
	"go.uber.org/zap"
)

var PluginManager = NewManager()
var ErrIgnore = errors.New("ignore")

type Manager struct {
	// plugins cache available SDK.IServer, key is plugin name
	plugins map[string]SDK.IServer
	mu      sync.Mutex
}

func NewManager() *Manager {
	return &Manager{plugins: make(map[string]SDK.IServer)}
}

// Get plugin's server side interface
func (pm *Manager) Get(name string) (SDK.IServer, bool) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	p, ok := pm.plugins[name]
	return p, ok
}

// GetAll returns all plugin interfaces
func (pm *Manager) GetAll() (plgs []SDK.IServer) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	plgs = make([]SDK.IServer, 0, len(pm.plugins))
	for _, p := range pm.plugins {
		plgs = append(plgs, p)
	}
	return plgs
}

// Load plugin from proto.Config which has already checked
// in Download and CheckSignature function, the real plugin
// and server has already packaged into SDK
func (m *Manager) Load(ctx context.Context, cfg proto.Config) (err error) {
	// configuration pre check
	if plg, ok := m.Get(cfg.Name); ok && !plg.IsExited() {
		if plg.Version() == cfg.Version {
			// ignore this if already started
			return ErrIgnore
		}
		zap.S().Infof("start to shutdown plugin %s, version %s", plg.Name(), plg.Version())
		plg.Shutdown()
	}
	if cfg.Signature == "" {
		cfg.Signature = cfg.Sha256
	}
	// plugin pre check
	plg, err := server.NewServer(ctx, agent.Workdir, &cfg)
	if err != nil {
		err = fmt.Errorf("plugin %s starts failed: %s", cfg.Name, err)
		zap.S().Error(err.Error())
		agent.SetAbnormal(err.Error())
		return
	}
	// start plugin goroutine
	plg.Wg().Add(3)
	go plg.Wait()
	go plg.Receive(pool.SDKGet, transport.Trans)
	go plg.Task()
	m.regist(plg.Name(), plg)
	return nil
}

func (pm *Manager) regist(name string, plg SDK.IServer) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.plugins[name] = plg
}

func (pm *Manager) unRegist(name string) (err error) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	plg, ok := pm.plugins[name]
	if !ok {
		return fmt.Errorf("plugin %s not found", name)
	}
	plg.Shutdown()
	delete(pm.plugins, name)
	if err = os.RemoveAll(plg.GetWorkingDirectory()); err != nil {
		agent.SetAbnormal(fmt.Sprintf("%s remove work dir failed: %s", name, err.Error()))
		return
	}
	return
}
