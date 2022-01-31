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
)

var (
	plgMInstance   *PluginManager
	plgManagerOnce *sync.Once
)

var (
	errDupPlugin = errors.New("duplicate plugin load")
)

// move to struct, dependency injection
type PluginManager struct {
	plugins *sync.Map
	syncCh  chan map[string]*proto.Config
}

func NewPluginManager() *PluginManager {
	plgManagerOnce.Do(func() {
		plgMInstance = &PluginManager{
			plugins: &sync.Map{},
			syncCh:  make(chan map[string]*proto.Config, 1),
		}
	})
	return plgMInstance
}

func (this *PluginManager) Get(name string) (*Plugin, bool) {
	plg, ok := this.plugins.Load(name)
	if ok {
		return plg.(*Plugin), ok
	}
	return nil, ok
}

func (this *PluginManager) GetAll() (plgs []*Plugin) {
	this.plugins.Range(func(key, value interface{}) bool {
		plg := value.(*Plugin)
		plgs = append(plgs, plg)
		return true
	})
	return
}

func (this *PluginManager) Sync(cfgs map[string]*proto.Config) (err error) {
	select {
	case this.syncCh <- cfgs:
	default:
		err = errors.New("plugins are syncing or context has been cancled")
	}
	return
}

func (this *PluginManager) Register(name string, plg *Plugin) {
	this.plugins.Store(name, plg)
}

func Load(ctx context.Context, config proto.Config) (err error) {
	plgManager := NewPluginManager()
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
