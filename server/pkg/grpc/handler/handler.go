// Handler handles the event from agent, including parsing, counting, storing
package handler

import (
	"hboat/pkg/grpc/transfer/pool"
	pb "hboat/pkg/grpc/transfer/proto"
)

var EventHandler = make(map[int32]Event)

type Event interface {
	ID() int32
	Name() string
	Handle(m map[string]string, req *pb.RawData, conn *pool.Connection) error // Handle the data
}

func RegistEvent(e Event) {
	EventHandler[e.ID()] = e
}
