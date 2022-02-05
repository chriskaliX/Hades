package plugin

import (
	"agent/agent"
	"agent/proto"
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
)

var (
	errDupPlugin = errors.New("duplicate plugin load")
)

func Load(ctx context.Context, config proto.Config) (err error) {
	plgManager := NewManager()
	loadedPlg, ok := plgManager.Get(config.GetName())
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
	plg, err := NewPlugin(ctx, config)
	if err != nil {
		return
	}
	// start goroutine
	// TODO: control the goroutine with context.Context
	plg.wg.Add(3)
	go plg.Wait()
	go plg.Receive()
	go plg.Task()
	plgManager.Register(plg.Name(), plg)
	return nil
}

func Startup(ctx context.Context, wg *sync.WaitGroup) {
	plgManager := NewManager()
	defer wg.Done()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			plgManager.UnregisterAll()
			return
		case cfgs := <-plgManager.syncCh:
			// 加载插件
			for _, cfg := range cfgs {
				if cfg.Name != agent.Product {
					err := Load(ctx, *cfg)
					// 相同版本的同名插件正在运行，无需操作
					if err == errDupPlugin {
						continue
					}
					if err != nil {
						// TODO: log here
						zap.S().Error(err)
					} else {
						// TODO: log here
					}
				}
			}
			// 移除插件
			for _, plg := range plgManager.GetAll() {
				if _, ok := cfgs[plg.Name()]; !ok {
					plg.Shutdown()
					plgManager.plugins.Delete(plg.Name())
					if err := os.RemoveAll(plg.GetWorkingDirectory()); err != nil {
						// TODO: log here
					}
				}
			}
		}
	}
}
