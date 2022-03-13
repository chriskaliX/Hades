package plugin

import (
	"agent/proto"
	"errors"
	"sync"
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

func (m *Manager) Get(name string) (*Plugin, bool) {
	plg, ok := m.plugins.Load(name)
	if ok {
		return plg.(*Plugin), ok
	}
	return nil, ok
}

func (m *Manager) GetAll() (plgs []*Plugin) {
	m.plugins.Range(func(_, value interface{}) bool {
		plg := value.(*Plugin)
		plgs = append(plgs, plg)
		return true
	})
	return
}

func (m *Manager) Sync(cfgs map[string]*proto.Config) (err error) {
	select {
	case m.syncCh <- cfgs:
	default:
		err = errors.New("plugins are syncing or context has been cancled")
	}
	return
}

func (m *Manager) Register(name string, plg *Plugin) {
	m.plugins.Store(name, plg)
}

func (m *Manager) UnRegister(name string) {
	m.plugins.Delete(name)
}

func (m *Manager) UnregisterAll() {
	subWg := &sync.WaitGroup{}
	m.plugins.Range(func(_, value interface{}) bool {
		subWg.Add(1)
		plg := value.(*Plugin)
		go func() {
			defer subWg.Done()
			plg.Shutdown()
			plg.wg.Wait()
			m.plugins.Delete(plg.Name())
		}()
		return true
	})
	subWg.Wait()
}
