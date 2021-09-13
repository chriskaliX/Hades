package network

import (
	"errors"
	"fmt"
	"time"
)

// 网络连接动作, 都需要实现这个
type INetRetry interface {
	// 网络配置初始化
	Init() error
	// 连接动作
	Connect() error
	// String 类
	String() string
	// 最大尝试次数
	GetMaxRetry() uint
	// 获取 Mod
	GetHashMod() uint
	// 关闭
	Close()
}

type Context struct {
	Shutdown    bool // 关闭连接指令
	RetryStatus bool // 连接状态, true代表尝试完毕, false 代表尝试中
}

// 连接统一使用接口
func (c *Context) IRetry(netRetry INetRetry) error {
	c.RetryStatus = true
	defer func() {
		c.RetryStatus = false
	}()
	// 初始化动作
	if err := netRetry.Init(); err != nil {
		return err
	}

	// 获取 最长尝试值 和 HashMod
	maxRetries := netRetry.GetMaxRetry()
	hashMod := netRetry.GetHashMod()

	var (
		retries uint
		delay   uint
	)

	for {
		if c.Shutdown {
			return errors.New("shutdown is true")
		}

		if maxRetries > 0 && retries >= maxRetries {
			return errors.New("over maxtries")
		}

		if e := netRetry.Connect(); e != nil {
			delay = 1 << retries
			if delay == 0 {
				delay = 1
			}
			delay = delay * hashMod
			fmt.Printf("Trying %s after %d seconds , retries:%d,error:%v\n", netRetry.String(), delay, retries, e)
			retries = retries + 1
			time.Sleep(time.Second * time.Duration(delay))
		} else {
			return nil
		}
	}
}

// 关闭统一使用接口
func (c *Context) IClose(netRetry INetRetry) {
	// log
	c.Shutdown = true
	fmt.Printf("shutdown %s ", netRetry.String())
	for {
		if !c.RetryStatus {
			netRetry.Close()
		}
		time.Sleep(time.Second * time.Duration(1))
	}
}
