package transport

import (
	"agent/config"
	"agent/global"
	"agent/transport/connection"
	"context"
	"sync"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
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
	defer wg.Done()
	for {
		cmd, err := c.Recv()
		if err != nil {
			zap.S().Error(err)
			return
		}
		config.Load(*cmd)
	}
}
