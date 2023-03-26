package connection

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// INetRetry packet the network connection behavior
type INetRetry interface {
	// Connect is the actual network action.
	Connect(context.Context) error
	// String returns the name of the network
	String() string
}

func IRetry(ctx context.Context, netRetry INetRetry, config Config) (err error) {
	var retries, delay uint
	ticker := time.NewTicker(config.BeforeDelay)
	defer ticker.Stop()
	select {
	case <-ctx.Done():
		return
	case <-ticker.C:
	}
	zap.S().Infof("iretry %s start connection after %d secs", netRetry.String(), int(config.BeforeDelay.Seconds()))
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if retries >= config.MaxRetry {
				err = fmt.Errorf("abandon %s after %d retries", netRetry.String(), retries)
				zap.S().Error(err)
				return err
			}
			if e := netRetry.Connect(ctx); e != nil {
				delay = 1 << retries
				if delay == 0 {
					delay = 1
				}
				delay = delay * uint(config.Multiplier)
				if delay >= config.MaxDelaySec {
					delay = config.MaxDelaySec
				}
				retries++
				zap.S().Warnf("trying %s after %d seconds, retries:%d, error:%v", netRetry.String(), delay, retries, e)
				ticker.Reset(time.Second * time.Duration(delay))
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			} else {
				zap.S().Info(fmt.Sprintf("%s connection is established", netRetry.String()))
				return nil
			}
		}
	}
}
