package mongo

import (
	"context"
	"fmt"
	"hboat/pkg/basic/utils"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

const (
	// database name
	dbName = "hades"
	// normal collections
	agentCol  = "agent"
	pluginCol = "plugin"
	assetCol  = "asset"
	userCol   = "user"
	recordCol = "log_record"
	// Time series collections
	// agent_metrics format: sys_cpu, agent_cpu, sys_mem, agent_mem // adding networking afterwards
	// plugin_metrics format: cpu, rss, tx_tps, tx_speed
	metricCol = "metric"
)

var MongoProxyImpl = &MongoProxy{}

type MongoProxy struct {
	client *mongo.Client
	// Collection
	StatusC *mongo.Collection
	PluginC *mongo.Collection
	AssetC  *mongo.Collection
	UserC   *mongo.Collection
	RecordC *mongo.Collection
	MetricC *mongo.Collection
}

func (m *MongoProxy) Init(uri string, poolsize uint64) error {
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
	m.client = mongoClient
	m.StatusC = m.client.Database(dbName).Collection(agentCol)
	m.PluginC = m.client.Database(dbName).Collection(pluginCol)
	m.AssetC = m.client.Database(dbName).Collection(assetCol)
	m.UserC = m.client.Database(dbName).Collection(userCol)
	m.RecordC = m.client.Database(dbName).Collection(recordCol)
	// metrics. mongodb version over 5.0 is needed.
	if err := m.timeCollectionPreCreate(
		m.client.Database(dbName),
		metricCol,
		options.TimeSeries().SetTimeField("timestamp").SetGranularity("minutes").SetMetaField("metrics")); err != nil {
		return err
	}
	m.MetricC = m.client.Database(dbName).Collection(metricCol)

	// backend admin user init
	res := m.UserC.FindOne(context.Background(), bson.M{"username": "admin"})
	if res.Err() == mongo.ErrNoDocuments {
		passwd := utils.RandStringRunes(6)
		err := CreateUser("admin", passwd, 0)
		if err != nil {
			return err
		}
		fmt.Println(passwd)
	}
	return nil
}

func (m *MongoProxy) Client() *mongo.Client { return m.client }

func (m *MongoProxy) timeCollectionPreCreate(db *mongo.Database, colName string, tso *options.TimeSeriesOptions) error {
	if m.client == nil {
		return fmt.Errorf("mongo client is not valid")
	}
	names, err := db.ListCollectionNames(context.TODO(), bson.D{})
	if err != nil {
		return err
	}
	var match = false
	for _, name := range names {
		if name == colName {
			match = true
		}
	}
	if !match {
		// As default, we get metrics ans save them for 7 days
		opts := options.CreateCollection().SetTimeSeriesOptions(tso).SetExpireAfterSeconds(3 * 24 * 60 * 60)
		return db.CreateCollection(context.TODO(), colName, opts)
	}
	return nil
}
