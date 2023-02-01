package basic

import (
	"context"
	"fmt"
	"hboat/pkg/basic/mongo"
	"hboat/pkg/basic/redis"
	"hboat/pkg/basic/utils"
	"hboat/pkg/conf"

	"go.mongodb.org/mongo-driver/bson"

	mongodb "go.mongodb.org/mongo-driver/mongo"
)

func Init() error {
	// init the datasources
	if err := mongo.NewMongoDB(conf.Config.Mongo.URI, conf.Config.Mongo.PoolSize); err != nil {
		return err
	}
	if err := redis.NewRedisClient(
		conf.Config.Redis.Addrs,
		conf.Config.Redis.MasterName,
		conf.Config.Redis.Password,
		redis.RedisMode(conf.Config.Redis.Mode)); err != nil {
		return err
	}
	// init the admin
	res := mongo.UserC.FindOne(context.Background(), bson.M{"username": "admin"})
	if res.Err() == mongodb.ErrNoDocuments {
		passwd := utils.RandStringRunes(6)
		err := mongo.CreateUser("admin", passwd, 0)
		if err != nil {
			return err
		}
		fmt.Println(passwd)
	}
	return nil
}
