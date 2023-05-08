package mongo

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

const (
	dbName    = "hades"
	agentCol  = "agent"
	pluginCol = "plugin"
	assetCol  = "asset"
	userCol   = "user"
	recordCol = "log_record"
)

// Client
var Inst *mongo.Client

// Collection
var StatusC *mongo.Collection
var PluginC *mongo.Collection
var AssetC *mongo.Collection
var UserC *mongo.Collection
var RecordC *mongo.Collection

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
	Inst = mongoClient

	StatusC = Inst.Database(dbName).Collection(agentCol)
	PluginC = Inst.Database(dbName).Collection(pluginCol)
	AssetC = Inst.Database(dbName).Collection(assetCol)
	UserC = Inst.Database(dbName).Collection(userCol)
	RecordC = Inst.Database(dbName).Collection(recordCol)
	// pre check user admin and print the passwd
	return nil
}
