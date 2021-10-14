package transport

import (
	"agent/config"
	"agent/global"
	"agent/transport/connection"
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/internal/transport"
)

func Run() {
	conn, err := connection.New()
	if err != nil {
		zap.S().Panic("No network is available")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		conn.Close()
	}()
	client, err := global.NewTransferClient(conn).Transfer(ctx, grpc.UseCompressor("snappy"))
	if err != nil {
		zap.S().Panic(err)
	}
	wg := sync.WaitGroup{}
	wg.Add(2)
	go handleSend(&wg, client)
	go handleReceive(&wg, client)
	wg.Wait()
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
		err = Check(cmd)
		if err != nil {
			continue
		}

	}
}

func Check(a *global.Command) error {
	if a.AgentCtrl < 1 || a.AgentCtrl > 3 {
		return errors.New("AgentCtrl flag not valid")
	}
	switch a.AgentCtrl {
	case 1:
	case 2:
		if a.Message == nil {
			return errors.New("no Message")
		}
		version := a.Message["Version"]
		if version == global.Version {
			return errors.New("No need to update")
		}
	case 3:
		w := &config.WhiteListConfig{}
		if a.Message == nil {
			return errors.New("no whitelists")
		}
		// 解析
		// 又做了一个中间转换? 感觉没必要, 后续代码简化了
		var rules []config.Rule
		for key, value := range a.Message {
			rule := &config.Rule{
				Field: key,
				Raw:   value,
			}
			rules = append(rules, *rule)
		}
		w.Rules = rules
		return w.Check()
	}
	return nil
}

func Load(a *global.Command) {
	switch a.AgentCtrl {
	case 1:
		os.Exit(0)
	case 2:
		// 这里自升级, 看一下 https://github.com/inconshreveable/go-update
		// 参考 https://github.com/sanbornm/go-selfupdate/
		// todo:
		transport.Download(a.Message["DownloadUrl"])
	}
}
