// handler handles the grpc connection
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"hboat/grpc/transfer/pool"
	pb "hboat/grpc/transfer/proto"

	"hboat/config"
	ds "hboat/datasource"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"google.golang.org/grpc/peer"
)

// Only instance for the grpc service, updates the collections in
// this status.
var statusC *mongo.Collection

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

	_, err = statusC.UpdateOne(context.Background(), bson.M{"agent_id": agentID},
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
			handleData(data, conn)
		}
	}
}

// handleData handles received data
//
// TODO: heartbeat to influxdb or ES
// Handle processes
func handleData(req *pb.RawData, conn *pool.Connection) {
	intranet_ipv4 := strings.Join(req.IntranetIPv4, ",")
	intranet_ipv6 := strings.Join(req.IntranetIPv6, ",")
	extranet_ipv4 := strings.Join(req.ExtranetIPv4, ",")
	extranet_ipv6 := strings.Join(req.ExtranetIPv6, ",")

	for _, value := range req.GetData() {
		dataType := value.DataType
		switch {
		// agent-heartbeat
		case dataType == 1:
			data := make(map[string]interface{}, 40)
			data["intranet_ipv4"] = intranet_ipv4
			data["intranet_ipv6"] = intranet_ipv6
			data["extranet_ipv4"] = extranet_ipv4
			data["extranet_ipv6"] = extranet_ipv6
			data["product"] = req.Product
			data["hostname"] = req.Hostname
			data["version"] = req.Version
			for k, v := range value.Body.Fields {
				// skip special field, hard-code
				if k == "platform_version" || k == "version" {
					data[k] = v
					continue
				}
				fv, err := strconv.ParseFloat(v, 64)
				if err == nil {
					data[k] = fv
				} else {
					data[k] = v
				}
			}
			conn.LastHBTime = time.Now().Unix()
			statusC.UpdateOne(context.Background(), bson.M{"agent_id": req.AgentID},
				bson.M{"$set": bson.M{"agent_detail": data, "last_heartbeat_time": conn.LastHBTime}})
			conn.SetAgentDetail(data)
		// plugin-heartbeat
		case dataType == 2:
			data := make(map[string]interface{})
			for k, v := range value.Body.Fields {
				// skip special field, hard-code
				if k == "pversion" {
					data[k] = v
					continue
				}
				fv, err := strconv.ParseFloat(v, 64)
				if err == nil {
					data[k] = fv
				} else {
					data[k] = v
				}
			}
			// Added heartbeat_time with plugin
			data["last_heartbeat_time"] = time.Now().Unix()
			// Do not cover on this
			statusC.UpdateOne(context.Background(), bson.M{"agent_id": req.AgentID},
				bson.M{"$set": bson.M{"plugin_detail." + value.Body.Fields["name"]: data}})
			conn.SetPluginDetail(value.Body.Fields["name"], data)
		case dataType == 2001, dataType == 1001, dataType == 5001, dataType == 3004:
			var field string
			switch dataType {
			case 5001:
				field = "sockets"
			case 3004:
				field = "users"
			case 1001:
				field = "processes"
			case 2001:
				field = "crons"
			}
			data := make([]map[string]interface{}, 0)
			err := json.Unmarshal([]byte(value.Body.Fields["data"]), &data)
			if err != nil {
				return
			}
			options := options.Update().SetUpsert(true)

			if _, err = ds.AssetC.UpdateOne(context.Background(), bson.M{"agent_id": req.AgentID},
				bson.M{"$set": bson.M{field: data}}, options); err != nil {
				//log
				return
			}
		// For now, we only take care some basic record from linux and windows, like processes,
		// sockets and so on, which should be collected by plugin collector. The others datas,
		// just put it in kafka. Maybe, we'll update the agent, let the agent upload these to
		// kafka directly
		//
		// TODO: kafka upload under dev

		// windows
		case dataType >= 100 && dataType <= 400:
			for _, item := range req.Item {
				// backport for windows for temp
				ParseWinDataDispatch(item.Fields, req, int(dataType))
			}
		default:
			// TODO
		}
	}
}

func init() {
	mongoClient, err := ds.NewMongoDB(config.MongoURI, 5)
	if err != nil {
		panic(err)
	}
	statusC = mongoClient.Database(ds.Database).Collection(config.MAgentStatusCollection)
}
