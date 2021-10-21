package grpctrans

import (
	pb "hadeserver/grpctrans/protobuf"
)

// 任务精确性, 要具体到 agentID, 所以每一个 AgentID 需要维护自己的一个 Command List
type GRPCPool struct {
	// 每一个 AgentID 对应到一个 Connection
}

// 每一个 Connection 维护一个资产信息
type Connection struct {
	// 每一个维护一个 Commond List
	CommandChan chan *pb.Command

	// 资产信息, 我再这里把外网 IP 剔除了, NetType 剔除了
	AgentID           string                   `json:"agent_id"`
	Addr              string                   `json:"addr"`
	CreateAt          int64                    `json:"create_at"`
	Cpu               float64                  `json:"cpu"`
	Memory            int64                    `json:"memory"`
	LastHeartBeatTime int64                    `json:"last_heartbeat_time"`
	HostName          string                   `json:"hostname"`
	Version           string                   `json:"version"`
	IntranetIPv4      []string                 `json:"intranet_ipv4"`
	IntranetIPv6      []string                 `json:"intranet_ipv6"`
	IO                float64                  `json:"io"`
	Slab              int64                    `json:"slab"`
	Plugin            []map[string]interface{} `json:"plugins"`
}
