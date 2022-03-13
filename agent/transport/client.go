package transport

import (
	"agent/core"
	"agent/proto"
	"context"
	"sync"
	"time"

	_ "agent/transport/compressor"
	"agent/transport/connection"

	"go.uber.org/zap"
	"google.golang.org/grpc"
)

// retries here, and some bugs
// TODO: not as I expected, but run firstly
func Startup(ctx context.Context, wg *sync.WaitGroup) {
	// TODO:ctx fix
	defer wg.Done()
	subWg := &sync.WaitGroup{}
	defer subWg.Wait()
	for {
		conn, err := connection.New(ctx)
		if err != nil {
			return
		}
		var client proto.Transfer_TransferClient
		subCtx, cancel := context.WithCancel(ctx)
		client, err = proto.NewTransferClient(conn).Transfer(subCtx, grpc.UseCompressor("snappy"))
		if err == nil {
			subWg.Add(2)
			go handleSend(subCtx, subWg, client)
			go func() {
				// 收到错误后取消服务
				handleReceive(subCtx, subWg, client)
				cancel()
			}()
			// stuck here
			subWg.Wait()
		} else {
			zap.S().Error(err)
		}
		cancel()
		zap.S().Info("transfer has been canceled,wait next try to transfer for 5 seconds")
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second * 5):
		}
	}
}

// only transport heartbeat, status and so on...
func handleSend(ctx context.Context, wg *sync.WaitGroup, c proto.Transfer_TransferClient) {
	defer wg.Done()
	defer c.CloseSend()
	zap.S().Info("send handler running")
	interval := time.NewTicker(time.Millisecond * 100)
	for {
		select {
		case <-ctx.Done():
			return
		case <-interval.C:
			core.DefaultTrans.Send(c)
		}
	}
}

func handleReceive(ctx context.Context, wg *sync.WaitGroup, c proto.Transfer_TransferClient) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
		// stuck here, may not helpful
		default:
			if err := core.DefaultTrans.Receive(c); err != nil {
				return
			}
		}
	}
}
