package ebpf

import (
	"context"

	"github.com/cilium/ebpf/rlimit"
	"go.uber.org/zap"
)

// ebpf 主程序, 真正的 runner
func Tracer() error {
	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	if err := rlimit.RemoveMemlock(); err != nil {
		zap.S().Error(err)
		return err
	}

	tracerProbe := &TracerProbe{}
	if err := tracerProbe.Init(ctx); err != nil {
		return err
	}

	defer tracerProbe.Close()

	if err := tracerProbe.Run(); err != nil {
		return err
	}
	zap.S().Info("tracer finished")
	return nil
}
