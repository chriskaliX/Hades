package handler

import (
	"context"
	"hboat/grpc/transfer/pool"
	"hboat/pkg/basic/mongo"
	pb "hboat/grpc/transfer/proto"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	mongod "go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// TaskAck handles data_type 5100 — the completion acknowledgement that
// plugins send after finishing an on-demand collection task.
//
// Document schema in `task_ack` collection:
//
//	{
//	  "token":     "<uuid>",     // unique task token
//	  "agent_id":  "<uuid>",
//	  "status":    "success"|"failed",
//	  "msg":       "<error message or empty>",
//	  "timestamp": <unix seconds>
//	}
//
// Design note: asset records are written by DefaultWorker via an async channel
// that flushes to MongoDB every 3 seconds. The ack arrives on the same gRPC
// stream right after all asset records, but the asset BulkWrite hasn't happened
// yet. To avoid the frontend seeing "success" while asset data is still in-flight,
// we delay updating the ack status by 4 seconds for the success case only.
// Failed acks are written immediately so the user sees the error without delay.
type TaskAck struct{}

var _ Event = (*TaskAck)(nil)

func (t *TaskAck) ID() int32    { return 5100 }
func (t *TaskAck) Name() string { return "task_ack" }

func (t *TaskAck) Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error {
	token, ok := m["token"]
	if !ok || token == "" {
		return nil
	}
	status := m["status"]
	msg := m["msg"]
	agentID := req.AgentID

	if status == "success" {
		// Delay so the asset worker's 3-second BulkWrite completes first.
		go func() {
			time.Sleep(4 * time.Second)
			writeTaskAck(token, agentID, status, msg)
		}()
		return nil
	}
	// Failed: write immediately so the user sees the error without delay.
	return writeTaskAck(token, agentID, status, msg)
}

func writeTaskAck(token, agentID, status, msg string) error {
	// Only update status-related fields; preserve create_at and data_type from the pre-insert.
	update := bson.M{"$set": bson.M{
		"status":    status,
		"msg":       msg,
		"finish_at": time.Now().Unix(),
	}}
	filter := bson.M{"token": token}
	opts := options.Update().SetUpsert(true)
	_, err := mongo.MongoProxyImpl.TaskAckC.UpdateOne(
		context.Background(), filter, update, opts,
	)
	return err
}

// EnsureIndexes is called once at startup; indexes are created in mongo.Init()
// via the MongoProxy, so nothing extra is needed here.
var _ = mongod.ErrNoDocuments // suppress unused import

func init() { RegistEvent(&TaskAck{}) }
