package plugin

import (
	"agent/agent"
	"agent/proto"
	"agent/utils"
	"context"
	"errors"
	"os"
	"os/exec"
	"path"
	"sync"
	"syscall"
	"time"
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
	workingDirectory := path.Join(agent.WorkingDirectory, "plugin", config.Name)
	execPath := path.Join(workingDirectory, config.Name)
	if err := utils.CheckSignature(execPath, config.Signature); err != nil {
		if err = utils.Download(ctx, execPath, config); err != nil {
			return err
		}
	}
	cmd := exec.Command(execPath)
	// There are some important concept of pid. pid/tgid (already known)
	// pgid means process group id, Reference: https://blog.csdn.net/caoshangpa/article/details/80140888
	// @Reference: https://studygolang.com/articles/10083
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Dir = workingDirectory
	var errFile *os.File
	errFile, err = os.OpenFile(execPath+".stderr", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o0600)
	if err != nil {
		return
	}
	defer errFile.Close()
	cmd.Stderr = errFile
	// TODO: figure this
	if config.Detail != "" {
		cmd.Env = append(cmd.Env, "DETAIL="+config.Detail)
	}
	// init plugin
	plg, err := NewPlugin(config)
	plg.SetCmd(cmd)
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
