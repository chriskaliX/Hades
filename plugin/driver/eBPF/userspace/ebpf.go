package userspace

import (
	"context"

	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
)

// ebpf 主程序, 真正的 runner
func Hades() error {
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	if err := rlimit.RemoveMemlock(); err != nil {
		zap.S().Error(err)
		return err
	}

	hadesProbe := &HadesProbe{}
	if err := hadesProbe.Init(ctx); err != nil {
		return err
	}

	defer hadesProbe.Close()

	if err := hadesProbe.Run(); err != nil {
		return err
	}
	zap.S().Info("tracer finished")
	return nil
}
