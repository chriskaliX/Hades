package datasource

import (
	"context"
	"hboat/pkg/config"
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
	UserCol        = "user"
)

// Client
var MongoInst *mongo.Client

// Collection
var StatusC *mongo.Collection
var PluginC *mongo.Collection
var AssetC *mongo.Collection
var UserC *mongo.Collection

func NewMongoDB(uri string, poolsize uint64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var opt options.ClientOptions
	opt.SetMaxPoolSize(poolsize)
	opt.SetReadPreference(readpref.SecondaryPreferred())
	mongoClient, err := mongo.Connect(ctx, options.Client().ApplyURI(uri), &opt)
	if err != nil {
		return err
	}
	// quit if mongo ping failed
	if err = mongoClient.Ping(ctx, nil); err != nil {
		return err
	}
	MongoInst = mongoClient

	StatusC = MongoInst.Database(Database).Collection(config.MAgentStatusCollection)
	PluginC = MongoInst.Database(Database).Collection(PluginCol)
	AssetC = MongoInst.Database(Database).Collection(AssetCol)
	UserC = MongoInst.Database(Database).Collection(UserCol)
	// pre check user admin and print the passwd
	return nil
}
