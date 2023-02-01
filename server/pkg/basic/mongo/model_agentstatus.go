package mongo

import (
	"hboat/pkg/conf"
	"time"
)

type AgentStatus struct {
	AgentID      string                            `bson:"agent_id"`
	Addr         string                            `bson:"addr"`
	Status       bool                              `bson:"status"`
	CreateAt     int64                             `bson:"create_at"`
	LastHBTime   int64                             `bson:"last_heartbeat_time"`
	AgentDetail  map[string]interface{}            `bson:"agent_detail"`
	PluginDetail map[string]map[string]interface{} `bson:"plugin_detail"`
}

// IsOnline is a wrapper to check if the status of agent by it's
// create time and heartbeat time
func (a AgentStatus) IsOnline() bool {
	var baseTime int64
	if a.CreateAt > a.LastHBTime {
		baseTime = a.CreateAt
	} else {
		baseTime = a.LastHBTime
	}
	if !a.Status {
		return false
	}
	if time.Now().Unix()-baseTime <= int64(conf.Config.Backend.AgentHBOfflineSec) {
		return true
	}
	return false
}
