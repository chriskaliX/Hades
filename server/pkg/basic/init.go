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
	if err := mongo.NewMongoDB(conf.MongoURI, 5); err != nil {
		return err
	}
	if err := redis.NewRedisClient(
		conf.RedisAddrs,
		conf.RedisMasterName,
		conf.RedisPassword,
		conf.RedisMode); err != nil {
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
