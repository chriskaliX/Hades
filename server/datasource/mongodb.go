package datasource

import (
	"context"
	"hboat/config"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

const (
	Database       = "hades"
	AgentStatusCol = "agentstatus"
	PluginCol      = "plugin"
	AssetCol       = "asset"
)

// Client
var MongoInst *mongo.Client

// Collection
var StatusC *mongo.Collection
var PluginC *mongo.Collection
var AssetC *mongo.Collection

func NewMongoDB(uri string, poolsize uint64) (*mongo.Client, error) {
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	var opt options.ClientOptions
	opt.SetMaxPoolSize(poolsize)
	opt.SetReadPreference(readpref.SecondaryPreferred())
	mongoClient, err := mongo.Connect(ctx, options.Client().ApplyURI(uri), &opt)
	if err != nil {
		return nil, err
	}
	// quit if mongo ping failed
	if err = mongoClient.Ping(ctx, nil); err != nil {
		return nil, err
	}
	return mongoClient, nil
}

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
	if time.Now().Unix()-baseTime <= config.AgentHBSec {
		return true
	}
	return false
}

func init() {
	var err error
	MongoInst, err = NewMongoDB(config.MongoURI, 5)
	if err != nil {
		panic(err)
	}
	StatusC = MongoInst.Database(Database).Collection(config.MAgentStatusCollection)
	PluginC = MongoInst.Database(Database).Collection(PluginCol)
	AssetC = MongoInst.Database(Database).Collection(AssetCol)
}
