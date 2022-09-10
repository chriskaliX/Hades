package plugin

import (
	"agent/agent"
	"agent/proto"
	"agent/transport"
	"agent/transport/pool"
	"context"
	"errors"
	"os"
	"sync"

	"github.com/chriskaliX/SDK/transport/protocol"
	"github.com/chriskaliX/SDK/transport/server"
	"go.uber.org/zap"
)

var (
	errDupPlugin = errors.New("duplicate plugin load")
)

func Load(ctx context.Context, config proto.Config) (err error) {
	loadedPlg, ok := DefaultManager.Get(config.GetName())
	// logical problem
	if ok {
		if loadedPlg.Version() == config.GetVersion() && !loadedPlg.IsExited() {
			return errDupPlugin
		}
		if loadedPlg.Version() != config.GetVersion() && !loadedPlg.IsExited() {
			loadedPlg.Shutdown()
		}
	}
	if config.GetSignature() == "" {
		config.Signature = config.GetSha256()
	}
	plg, err := server.NewServer(ctx, agent.Instance.Workdir, config)
	if err != nil {
		return
	}
	plg.Wg().Add(3)
	go plg.Wait()
	go plg.Receive(pool.SDKGet, transport.DTransfer)
	go plg.Task()
	DefaultManager.Register(plg.Name(), plg)
	return nil
}

func Startup(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			DefaultManager.UnregisterAll()
			return
		case cfgs := <-DefaultManager.syncCh:
			// 加载插件
			for _, cfg := range cfgs {
				if cfg.Name != agent.Product {
					err := Load(ctx, *cfg)
					// 相同版本的同名插件正在运行，无需操作
					if err == errDupPlugin {
						continue
					}
					if err != nil {
						zap.S().Error(err)
					} else {
						zap.S().Info("plugin has been loaded")
					}
				}
			}
			// 移除插件
			for _, plg := range DefaultManager.GetAll() {
				if _, ok := cfgs[plg.Name()]; !ok {
					plg.Shutdown()
					DefaultManager.UnRegister(plg.Name())
					if err := os.RemoveAll(plg.GetWorkingDirectory()); err != nil {
						zap.S().Error(err)
					}
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
				if plg, ok := DefaultManager.Get(task.GetObjectName()); ok {
					// Just for temp/ TODO
					if err := plg.SendTask((protocol.Task)(*task)); err != nil {
						zap.S().Error("send task to plugin: ", err)
					}
				} else {
					zap.S().Error("can't find plugin: ", task.GetObjectName())
				}
			case cfgs := <-transport.PluginConfigChan:
				if err := DefaultManager.Sync(cfgs); err != nil {
					zap.S().Error("config sync failed: ", err)
				}
			}
		}
	}()
}
