package transport

import (
	"agent/config"
	"agent/global"
	"agent/transport/connection"
	"agent/utils"
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// 这里的写法是错误直接Panic
func Run() {
	for {
		conn, err := connection.New()
		if err != nil {
			// zap.S().Panic("No network is available")
			// test
			zap.S().Error("No network is available")
			continue
		}
		ctx, cancel := context.WithCancel(context.Background())
		client, err := global.NewTransferClient(conn).Transfer(ctx, grpc.UseCompressor("snappy"))
		if err != nil {
			// zap.S().Panic(err)
			// 先err来debug
			zap.S().Error(err)
		}
		wg := sync.WaitGroup{}
		wg.Add(2)
		go handleSend(&wg, client)
		go handleReceive(&wg, client)
		wg.Wait()
		cancel()
		conn.Close()
		time.Sleep(10 * time.Minute)
	}
}

func handleSend(wg *sync.WaitGroup, c global.Transfer_TransferClient) {
	defer wg.Done()
	buffer := make([]*global.Record, 0, 10000)
	interval := time.NewTicker(time.Millisecond * 100)
	for {
		select {
		case records := <-global.GrpcChannel:
			{
				buffer = append(buffer, records...)
			}
		case <-interval.C:
			if len(buffer) == 0 {
				continue
			}
			// Create send request packet
			req := global.RawData{
				IntranetIPv4: global.PrivateIPv4,
				IntranetIPv6: global.PrivateIPv6,
				Hostname:     global.Hostname,
				AgentID:      global.AgentID,
				Timestamp:    time.Now().Unix(),
				Version:      global.Version,
				Pkg:          buffer,
			}
			err := c.Send(&req)
			// If you encounter an error when sending, exit directly
			if err != nil {
				zap.S().Error(err)
				return
			}
			// Clear buffer
			buffer = buffer[0:0]
		}
	}
}

func handleReceive(wg *sync.WaitGroup, c global.Transfer_TransferClient) {
	// 这里后续可能会复杂化，目前纯采集不需要下发扫描
	// 这里需要初始化, 没有和 server 建立连接, 不往下执行
	defer wg.Done()
	for {
		cmd, err := c.Recv()
		if err != nil {
			zap.S().Error(err)
			return
		}
		err = CheckAndLoad(cmd)
		if err != nil {
			continue
		}
	}
}

func CheckAndLoad(a *global.Command) error {
	switch a.AgentCtrl {
	case 1:
		os.Exit(0)
	case 2:
		// 这里自升级, 看一下 https://github.com/inconshreveable/go-update
		// 参考 https://github.com/sanbornm/go-selfupdate/
		// todo:

		// 开始绑定参数
		downloadConfig := &config.Download{}
		err := utils.Bind(a.Message, downloadConfig)
		if err != nil {
			return err
		}
		if downloadConfig.Version == global.Version {
			return errors.New("No need to update")
		}

		// 下载
		if err = Download([]string{downloadConfig.Url}, "Hades.tmp", downloadConfig.Sha256); err != nil {
			return err
		}
		// 重命名 - 这个名字暂时还对不上, 后期直接改掉就行
		err = os.Rename("Hades.tmp", "Hades")
		// 直接推出, 由守护进程拉起
		if err == nil {
			os.Exit(0)
		} else {
			os.Remove("Hades")
		}

	case 3:
		w := &config.WhiteList{}
		if err := utils.Bind(a.Message, w); err != nil {
			return err
		}
		if err := w.Check(); err != nil {
			return err
		}
		if err := w.Load(); err != nil {
			return err
		}
	default:
		return errors.New("AgentCtrl flag invalid")
	}
	return nil
}
