package connection

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

// INetRetry packet the network connection behavior
type INetRetry interface {
	Connect() error
	// String returns the name of the network
	String() string
	// GetMaxRetry returns the max retries of the connect action
	GetMaxRetry() uint
	// GetHashMod returns the random value
	GetHashMod() uint
	// GetHashInterval returns the interval of the connection
	// which is the basic time.
	GetInterval() uint
	// GetMaxDelay returns the max delay of the connection
	GetMaxDelay() uint
}

func IRetry(ctx context.Context, netRetry INetRetry) (err error) {
	var (
		maxRetries   uint
		maxDelay     uint
		hashMod      uint
		hashInterval uint
		retries      uint
		delay        uint
	)
	maxRetries = netRetry.GetMaxRetry()
	hashMod = netRetry.GetHashMod()
	maxDelay = netRetry.GetMaxDelay()
	hashInterval = netRetry.GetInterval()
	// pre-set for hashmod
	time.Sleep(time.Duration(hashMod) * time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if maxRetries > 0 && retries >= maxRetries {
				err = fmt.Errorf("abandon %s after %d retries.", netRetry.String(), retries)
				zap.S().Error(err)
				return err
			}
			if e := netRetry.Connect(); e != nil {
				delay = 1 << retries
				if delay == 0 {
					delay = 1
				}
				delay = delay * hashInterval
				// restrict delay
				if delay >= maxDelay {
					delay = maxDelay
				}
				retries = retries + 1
				zap.S().Info(fmt.Sprintf("Trying %s after %d seconds, retries:%d, error:%v", netRetry.String(), delay, retries, e))
				time.Sleep(time.Second * time.Duration(delay))
			} else {
				zap.S().Info(fmt.Sprintf("%s connection is established.", netRetry.String()))
				return nil
			}
		}
	}
}
