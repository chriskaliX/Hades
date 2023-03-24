package transport

import (
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
func Startup(ctx context.Context, wg *sync.WaitGroup) {
	var client proto.Transfer_TransferClient
	defer wg.Done()
	defer zap.S().Info("grpc deamon exits")
	zap.S().Info("grpc transport starts")
	subWg := &sync.WaitGroup{}
	for {
		select {
		case <-ctx.Done():
			return
		default:
			// get the connection
			conn, err := connection.GetConnection(ctx)
			if err != nil {
				continue
			}
			// generate sub-context and passes to the transfer client
			subCtx, cancel := context.WithCancel(ctx)
			if client, err = proto.NewTransferClient(conn).
				Transfer(subCtx, grpc.UseCompressor("snappy")); err != nil {
				zap.S().Errorf("grpc transfer failed: %s", err.Error())
				cancel()
				continue
			}
			// client start successfully, start the goroutines and wait
			subWg.Add(2)
			go handleSend(subCtx, subWg, client)
			go func() {
				handleReceive(subCtx, subWg, client)
				cancel()
			}()
			subWg.Wait()
			cancel()
			zap.S().Info("transfer has been canceled, start to reconnect")
		}
	}
}

// only transport heartbeat, status and so on...
func handleSend(ctx context.Context, wg *sync.WaitGroup, c proto.Transfer_TransferClient) {
	defer wg.Done()
	defer zap.S().Info("send handler is exited")
	defer c.CloseSend()
	zap.S().Info("send handler starts")
	ticker := time.NewTicker(time.Millisecond * 100)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := Trans.Send(c); err != nil {
				zap.S().Errorf("handle send failed: %s", err.Error())
			}
		}
	}
}

func handleReceive(ctx context.Context, wg *sync.WaitGroup, client proto.Transfer_TransferClient) {
	defer wg.Done()
	defer zap.S().Info("handle receive is exited")
	zap.S().Info("handle receive starts")
	for {
		select {
		case <-ctx.Done():
			return
		default:
			if err := Trans.Receive(client); err != nil {
				zap.S().Errorf("handle receive failed: %s", err.Error())
				return
			}
		}
	}
}
