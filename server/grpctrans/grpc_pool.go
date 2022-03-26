package grpctrans

import (
	"context"
	"errors"
	pb "hadeserver/grpctrans/protobuf"
	"sync"
)

var GlobalGRPCPool = &GRPCPool{}

// config.yml
// todo:
var ConnLimit = 1000

// 任务精确性, 要具体到 agentID, 所以每一个 AgentID 需要维护自己的一个 Command List
type GRPCPool struct {
	// 每一个 AgentID 对应到一个 Connection
	conn  sync.Map
	count int
}

// 获取 AgentId 对应的 Connection
func (g *GRPCPool) Get(agentID string) (*Connection, error) {
	tmp, ok := g.conn.Load(agentID)
	if !ok {
		return nil, errors.New("agentID not found")
	}
	return tmp.(*Connection), nil
}

// 删除对应的 Key
func (g *GRPCPool) Delete(agentID string) {
	g.conn.Delete(agentID)
	g.count = g.count - 1
}

func (g *GRPCPool) Add(agentID string, conn *Connection) error {
	_, ok := g.conn.Load(agentID)
	if ok {
		return errors.New("agentID exists")
	}
	g.conn.Store(agentID, conn)
	g.count += 1
	return nil
}

func (g *GRPCPool) CheckLimit() error {
	if g.count > ConnLimit {
		return errors.New("Connection Limited")
	}

	return nil
}

// 每一个 Connection 维护一个资产信息
type Connection struct {
	// 需要上下文来操控这个 Connection 的开关
	Ctx        context.Context    `json:"-"`
	CancelFunc context.CancelFunc `json:"-"`

	// 每一个维护一个 Commond List
	// 这里和字节不一样的是, 需要有主动查询功能
	CommandChan chan *pb.Command `json:"-"`

	// 资产信息, 我再这里把外网 IP 剔除了, NetType 剔除了, 没有 plugin 概念, 移除 plugins
	AgentID           string   `json:"agent_id"`
	Addr              string   `json:"addr"`
	CreateAt          int64    `json:"create_at"`
	Cpu               float64  `json:"cpu"`
	Memory            int64    `json:"memory"`
	LastHeartBeatTime int64    `json:"last_heartbeat_time"`
	HostName          string   `json:"hostname"`
	Version           string   `json:"version"`
	OSVersion         string   `json:"osversion"`
	IntranetIPv4      []string `json:"intranet_ipv4"`
	IntranetIPv6      []string `json:"intranet_ipv6"`
	IO                float64  `json:"io"`
	Slab              int64    `json:"slab"`
}
