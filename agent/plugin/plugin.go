package plugin

import (
	"agent/agent"
	"agent/transport"
	"context"
	"sync"

	"github.com/chriskaliX/SDK/config"
	"github.com/chriskaliX/SDK/transport/protocol"
	"go.uber.org/zap"
)

func Startup(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			PluginManager.UnregisterAll()
			return
		case cfgs := <-PluginManager.syncCh:
			// 加载插件
			for _, cfg := range cfgs {
				if cfg.Name == agent.Product {
					continue
				}
				if err := PluginManager.Load(ctx, *cfg); err != nil {
					zap.S().Error(err)
				} else {
					zap.S().Infof("plugin %s is loaded", cfg.Name)
				}
			}
			// 移除插件
			for _, plg := range PluginManager.GetAll() {
				if _, ok := cfgs[plg.Name()]; ok {
					continue
				}
				if err := PluginManager.UnRegister(plg.Name()); err != nil {
					zap.S().Error(err)
				} else {
					zap.S().Infof("plugin %s is removed", plg.Name())
				}
			}
		}
	}
}

func init() {
	go func() {
		for {
			select {
			case task := <-transport.PluginTaskChan:
				// In future, shutdown, update, restart will be in here
				if plg, ok := PluginManager.Get(task.GetObjectName()); ok {
					switch task.DataType {
					case config.TaskShutdown:
						zap.S().Infof("task shutdown plugin %s", plg.Name())
						PluginManager.UnRegister(plg.Name())
						return
					}
					if err := plg.SendTask((protocol.Task)(*task)); err != nil {
						zap.S().Error("send task to plugin: ", err)
					}
				} else {
					zap.S().Error("can't find plugin: ", task.GetObjectName())
				}
			case cfgs := <-transport.PluginConfigChan:
				if err := PluginManager.Sync(cfgs); err != nil {
					zap.S().Error("config sync failed: ", err)
				}
			}
		}
	}()
}
