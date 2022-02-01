package plugin

import (
	"agent/proto"
	"agent/resource"
	"errors"
	"os"
	"strconv"
	"sync"
	"time"
)

var (
	plgMInstance   *Manager
	plgManagerOnce sync.Once
)

// move to struct, dependency injection
type Manager struct {
	plugins *sync.Map
	syncCh  chan map[string]*proto.Config
}

func NewManager() *Manager {
	plgManagerOnce.Do(func() {
		plgMInstance = &Manager{
			plugins: &sync.Map{},
			syncCh:  make(chan map[string]*proto.Config, 1),
		}
	})
	return plgMInstance
}

func (this *Manager) Get(name string) (*Plugin, bool) {
	plg, ok := this.plugins.Load(name)
	if ok {
		return plg.(*Plugin), ok
	}
	return nil, ok
}

func (this *Manager) GetAll() (plgs []*Plugin) {
	this.plugins.Range(func(key, value interface{}) bool {
		plg := value.(*Plugin)
		plgs = append(plgs, plg)
		return true
	})
	return
}

func (this *Manager) Sync(cfgs map[string]*proto.Config) (err error) {
	select {
	case this.syncCh <- cfgs:
	default:
		err = errors.New("plugins are syncing or context has been cancled")
	}
	return
}

func (this *Manager) Register(name string, plg *Plugin) {
	this.plugins.Store(name, plg)
}

func (this *Manager) UnregisterAll() {
	subWg := &sync.WaitGroup{}
	this.plugins.Range(func(key, value interface{}) bool {
		subWg.Add(1)
		plg := value.(*Plugin)
		go func() {
			defer subWg.Done()
			plg.Shutdown()
			plg.wg.Wait()
			this.plugins.Delete(plg.Name())
		}()
		return true
	})
	subWg.Wait()
}

func (this *Manager) GetPlgStat(now time.Time) {
	plgs := this.GetAll()
	for _, plg := range plgs {
		if !plg.IsExited() {
			rec := &proto.Record{
				DataType:  1001,
				Timestamp: now.Unix(),
				Data: &proto.Payload{
					Fields: map[string]string{"name": plg.Name(), "pversion": plg.Version()},
				},
			}
			cpuPercent, rss, readSpeed, writeSpeed, fds, startAt, err := resource.GetProcResouce(plg.Pid())
			if err != nil {
				// TODO: log here
			} else {
				rec.Data.Fields["cpu"] = strconv.FormatFloat(cpuPercent, 'f', 8, 64)
				rec.Data.Fields["rss"] = strconv.FormatUint(rss, 10)
				rec.Data.Fields["read_speed"] = strconv.FormatFloat(readSpeed, 'f', 8, 64)
				rec.Data.Fields["write_speed"] = strconv.FormatFloat(writeSpeed, 'f', 8, 64)
				rec.Data.Fields["pid"] = strconv.Itoa(os.Getpid())
				rec.Data.Fields["fd_cnt"] = strconv.FormatInt(int64(fds), 10)
				rec.Data.Fields["started_at"] = strconv.FormatInt(startAt, 10)
			}
			rec.Data.Fields["du"] = strconv.FormatUint(resource.GetDirSize(plg.GetWorkingDirectory(), ""), 10)
			RxSpeed, TxSpeed, RxTPS, TxTPS := plg.GetState()
			rec.Data.Fields["rx_tps"] = strconv.FormatFloat(RxTPS, 'f', 8, 64)
			rec.Data.Fields["tx_tps"] = strconv.FormatFloat(TxTPS, 'f', 8, 64)
			rec.Data.Fields["rx_speed"] = strconv.FormatFloat(RxSpeed, 'f', 8, 64)
			rec.Data.Fields["tx_speed"] = strconv.FormatFloat(TxSpeed, 'f', 8, 64)
			// TODO: log here
			// core.Transmission(rec, false)
		}
	}
}
