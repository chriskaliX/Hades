package mongo

import "time"

type AlarmLevel string

const (
	Critical AlarmLevel = "critical"
	High     AlarmLevel = "high"
	Mid      AlarmLevel = "medium"
	Low      AlarmLevel = "low"
)

type AlarmStatus string

const (
	Unsolved AlarmStatus = "unsolved"
	Solved   AlarmStatus = "solved"
)

type Alarm struct {
	Name        string      `json:"name" bson:"name"`
	Level       AlarmLevel  `json:"level" bson:"level"`
	Type        string      `json:"type" bson:"type"`
	Status      AlarmStatus `json:"status" bson:"status"`
	AgentId     string      `json:"agent_id" bson:"agent_id"`
	GmtCreate   time.Time   `json:"gmt_create" bson:"gmt_create"`
	GmtModified time.Time   `json:"gmt_modified" bson:"gmt_modified"`
	Description interface{} `json:"description" bson:"description"`
}
