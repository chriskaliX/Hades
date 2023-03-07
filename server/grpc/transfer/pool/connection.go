package pool

import (
	"context"
	"sync"

	pb "hboat/grpc/transfer/proto"
)

// Connection describe grpc_connection instance by recording
// it's agent and plugin details
//
// From Elkeid
type Connection struct {
	Ctx          context.Context        `json:"-"`
	CancelFunc   context.CancelFunc     `json:"-"`
	CommandChan  chan *Command          `json:"-"`
	AgentID      string                 `json:"agent_id"`
	Addr         string                 `json:"addr"`
	CreateAt     int64                  `json:"create_at"`
	LastHBTime   int64                  `json:"last_heartbeat_time"`
	AgentDetail  map[string]interface{} `json:"agent_detail"`
	agentLock    sync.RWMutex
	PluginDetail map[string]map[string]interface{} `json:"plugin_detail"`
	pluginLock   sync.RWMutex
}

// Command is a wrapper of proto.Command, the Ready chan
type Command struct {
	Command *pb.Command
	Error   error
	Ready   chan bool
}

func (c *Connection) GetAgentDetail() map[string]interface{} {
	c.agentLock.RLock()
	defer c.agentLock.RUnlock()
	if c.AgentDetail == nil {
		return map[string]interface{}{}
	}
	return c.AgentDetail
}

func (c *Connection) SetAgentDetail(detail map[string]interface{}) {
	c.agentLock.Lock()
	defer c.agentLock.Unlock()
	c.AgentDetail = detail
}

func (c *Connection) SetPluginDetail(name string, detail map[string]interface{}) {
	c.pluginLock.Lock()
	defer c.pluginLock.Unlock()
	if c.PluginDetail == nil {
		c.PluginDetail = map[string]map[string]interface{}{}
	}
	c.PluginDetail[name] = detail
}

// TODO
func (c *Connection) DelPluginDetail(name string, detail map[string]interface{}) {}

func (c *Connection) GetPluginDetail(name string) map[string]interface{} {
	c.pluginLock.RLock()
	defer c.pluginLock.RUnlock()
	if c.PluginDetail == nil {
		return map[string]interface{}{}
	}
	plgDetail, ok := c.PluginDetail[name]
	if !ok {
		return map[string]interface{}{}
	}
	return plgDetail
}

func (c *Connection) GetPluginsList() []map[string]interface{} {
	c.pluginLock.Lock()
	defer c.pluginLock.Unlock()
	res := make([]map[string]interface{}, 0, len(c.PluginDetail))
	for k := range c.PluginDetail {
		res = append(res, c.PluginDetail[k])
	}
	return res
}
