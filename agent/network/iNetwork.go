package network

import (
	"errors"
	"fmt"
	"time"

	"go.uber.org/zap"
)

/*
	所有网络操作实现动作, 统一加强鲁棒性
*/
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
	// 关闭动作
	Close()
}

type Context struct {
	Shutdown    bool // 关闭连接指令
	RetryStatus bool // 连接状态, true代表尝试完毕, false 代表尝试中
}

/*
 * 连接使用统一动作
 * 指数回连防止出现网络上的雪崩效应
 * 2021-11-06, 在 grpc 接口上, 我们不应该直接断开, 而是在上限之后进行保持, 防止在 server 端因为意外下线一段时间后, 导致所有的 agent 端丢失
 */
func (c *Context) IRetry(netRetry INetRetry) (err error) {
	// 重试动作标识位
	c.RetryStatus = true
	defer func() {
		c.RetryStatus = false
	}()

	// 初始化动作
	if err = netRetry.Init(); err != nil {
		zap.S().Error(err)
		return
	}

	// 获取 最长尝试值 和 HashMod
	maxRetries := netRetry.GetMaxRetry()
	hashMod := netRetry.GetHashMod()

	var (
		retries uint
		delay   uint
	)

	// 开始重试
	for {
		if c.Shutdown {
			err = errors.New("shutdown is true")
			zap.S().Error(err)
			return err
		}

		if maxRetries > 0 && retries >= maxRetries {
			err = errors.New("over maxtries")
			zap.S().Error(err)
			return err
		}

		if e := netRetry.Connect(); e != nil {
			delay = 1 << retries
			if delay == 0 {
				delay = 1
			}
			delay = delay * hashMod
			// 对 delay 设置上限, 最长不超过 20 分钟, 来配合不退出这个策略
			if delay >= 1200 {
				delay = 1200
			}
			zap.S().Info(fmt.Sprintf("Trying %s after %d seconds, retries:%d, error:%v", netRetry.String(), delay, retries, e))
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
