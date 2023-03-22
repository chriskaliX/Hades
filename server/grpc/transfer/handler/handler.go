// handler handles the grpc connection
package handler

import (
	"context"
	"errors"
	"fmt"
	"time"

	"hboat/grpc/handler"
	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"
	"hboat/pkg/basic/mongo"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.uber.org/zap"
	"google.golang.org/grpc/peer"
)

// TransferHandler implements svc.TransferServer
type TransferHandler struct{}

func (h *TransferHandler) Transfer(stream pb.Transfer_TransferServer) (err error) {
	var agentID string
	var addr string

	// Receive the very first package once grpc established
	data, err := stream.Recv()
	if err != nil {
		return err
	}

	// Get the agentid and ip address from connection.
	agentID = data.AgentID
	p, ok := peer.FromContext(stream.Context())
	if !ok {
		return errors.New("client ip get error")
	}
	addr = p.Addr.String()
	fmt.Printf("Get connection %s from %s\n", agentID, addr)

	// Initialize the connection
	ctx, cancelFunc := context.WithCancel(context.Background())
	conn := pool.Connection{
		AgentID:     agentID,
		Addr:        addr,
		CreateAt:    time.Now().Unix(),
		CommandChan: make(chan *pool.Command),
		Ctx:         ctx,
		CancelFunc:  cancelFunc,
	}
	if err = pool.GlobalGRPCPool.Add(agentID, &conn); err != nil {
		return err
	}

	// Data update, also, update the address of the grpc for sendcommand
	// TODO: use channel or just put in kafka
	options := options.Update().SetUpsert(true)
	_, err = mongo.StatusC.UpdateOne(context.Background(), bson.M{"agent_id": agentID},
		bson.M{"$set": bson.M{
			"addr":                addr,
			"create_at":           conn.CreateAt,
			"agent_detail":        bson.M{"hostname": data.Hostname},
			"last_heartbeat_time": conn.CreateAt,
			"status":              true,
		}}, options)

	defer pool.GlobalGRPCPool.Delete(agentID)
	go recvData(stream, &conn)
	go sendData(stream, &conn)
	<-conn.Ctx.Done()
	return nil
}

func sendData(stream pb.Transfer_TransferServer, conn *pool.Connection) {
	defer conn.CancelFunc()

	for {
		select {
		case <-conn.Ctx.Done():
			return
		case cmd := <-conn.CommandChan:
			if cmd == nil {
				return
			}
			err := stream.Send(cmd.Command)
			if err != nil {
				cmd.Error = err
				close(cmd.Ready)
				return
			}
			cmd.Error = nil
			close(cmd.Ready)
		}
	}
}

func recvData(stream pb.Transfer_TransferServer, conn *pool.Connection) {
	defer conn.CancelFunc()
	for {
		select {
		case <-conn.Ctx.Done():
			return
		default:
			data, err := stream.Recv()
			if err != nil {
				return
			}
			for _, value := range data.GetData() {
				dataType := value.DataType
				eventHandler, ok := handler.EventHandler[dataType]
				if !ok {
					continue
				}
				err := eventHandler.Handle(value.Body.Fields, data, conn)
				if err != nil {
					zap.S().Errorf("event_handle", "agentid:%s, err:%s", data.AgentID, err.Error())
					continue
				}
				// TODO: kafka upload here
			}
		}
	}
}
