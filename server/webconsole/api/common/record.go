package common

import (
	"context"
	"hboat/pkg/basic/mongo"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
)

var OperatorEmpty string = ""

func LogRecord(c *gin.Context, msg string) error {
	username, ok := c.Get("username")
	if !ok {
		username = ""
	}
	_, err := mongo.MongoProxyImpl.RecordC.InsertOne(context.Background(), bson.M{
		"gmt_create": time.Now().Unix(),
		"message":    msg,
		"operator":   username,
	})
	return err
}
