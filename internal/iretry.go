package internal

import "context"

type INetRetry interface {
	Init() error
	Connect() error
	String() string
	GetMaxRetry() uint
	GetHashMod() uint
	Close()
}

type Context struct {
	context.Context
}

func (this *Context) IRetry(netRetry INetRetry) error {
	if e := netRetry.Init(); e != nil {
		return e
	}

	maxRetries := netRetry.GetMaxRetry()
	hashMod := netRetry.GetHashMod()

	var (
		retries uint
		delay   uint
	)

	for {
		if maxRetries > 0 && retries >= maxRetries {
			// ("Abandoning %s after %d retries.", netRetry.String(), retries)
		}
	}

	
}
