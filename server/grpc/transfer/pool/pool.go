package pool

import (
	"context"
	"errors"
	ds "hboat/datasource"
	pb "hboat/grpc/transfer/proto"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

// TODO just testing
const MaxConnection = 1000

var GlobalGRPCPool = NewGRPCPool()

type GRPCPool struct {
	// connPool cache the grpc connections
	// key is agent id and value is *Connection
	connPool map[string]*Connection
	connLock sync.RWMutex
}

func NewGRPCPool() *GRPCPool {
	return &GRPCPool{
		connPool: make(map[string]*Connection),
	}
}

func (g *GRPCPool) Get(agentID string) (*Connection, error) {
	g.connLock.RLock()
	defer g.connLock.RUnlock()
	conn, ok := g.connPool[agentID]
	if !ok {
		return nil, errors.New("agentID not found")
	}
	return conn, nil
}

func (g *GRPCPool) Add(agentID string, conn *Connection) error {
	_, err := g.Get(agentID)
	if err == nil {
		return errors.New("agentID already exists")
	}
	g.connLock.Lock()
	defer g.connLock.Unlock()
	g.connPool[agentID] = conn
	return nil
}

// Delete agentID from the connection pool. At the same time, we should remove
// the mongo instance
func (g *GRPCPool) Delete(agentID string) {
	g.connLock.Lock()
	defer g.connLock.Unlock()
	delete(g.connPool, agentID)
	ds.StatusC.UpdateOne(context.Background(), bson.M{"agent_id": agentID},
		bson.M{"$set": bson.M{"status": false}})
}

func (g *GRPCPool) Count() int {
	g.connLock.RLock()
	defer g.connLock.RUnlock()
	return len(g.connPool)
}

// SendCommand send command to specified agent_id
func (g *GRPCPool) SendCommand(agentID string, command *pb.Command) (err error) {
	conn, err := g.Get(agentID)
	if err != nil {
		return err
	}

	comm := &Command{
		Command: command,
		Error:   nil,
		Ready:   make(chan bool, 1),
	}

	select {
	case conn.CommandChan <- comm:
	case <-time.After(2 * time.Second):
		return errors.New("command channel is full")
	}
	// After sending the command, a wating action like Elkied should be implemented
	// for knowning the result of the command execution, use a notify latter
	select {
	case <-comm.Ready:
		return comm.Error
	case <-time.After(2 * time.Second):
		return errors.New("the command has been sent but get results timed out")
	}
}

func (g *GRPCPool) All() []*Connection {
	res := make([]*Connection, 0)
	g.connLock.RLock()
	defer g.connLock.RUnlock()
	for _, v := range g.connPool {
		conn := v
		res = append(res, conn)
	}
	return res
}
