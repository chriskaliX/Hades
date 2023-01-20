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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
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

func StartMongo() error {
	var err error
	MongoInst, err = NewMongoDB(config.MongoURI, 5)
	if err != nil {
		return err
	}
	StatusC = MongoInst.Database(Database).Collection(config.MAgentStatusCollection)
	PluginC = MongoInst.Database(Database).Collection(PluginCol)
	AssetC = MongoInst.Database(Database).Collection(AssetCol)
	return nil
}
