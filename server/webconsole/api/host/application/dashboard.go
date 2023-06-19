package application

import (
	"context"
	"hboat/api/common"
	"hboat/pkg/basic/mongo"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type dashboardResp struct {
	ContainerCount   int64 `json:"container_count"`
	ProcessCount     int64 `json:"process_count"`
	UserCount        int64 `json:"user_count"`
	SystemdCount     int64 `json:"systemd_count"`
	ApplicationCount int64 `json:"application_count"`
	CrontabCount     int64 `json:"crontab_count"`
	KmodCount        int64 `json:"kmod_count"`
}

const countLimit int64 = 99999

func Dashboard(c *gin.Context) {

	var resp dashboardResp

	containerCount, err := getCount(bson.M{"data_type": 3018})
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	resp.ContainerCount = containerCount
	processCount, err := getCount(bson.M{"data_type": 1001})
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	resp.ProcessCount = processCount
	userCount, err := getCount(bson.M{"data_type": 3004})
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	resp.UserCount = userCount
	systemdCount, err := getCount(bson.M{"data_type": 3011})
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	resp.SystemdCount = systemdCount
	applicationCount, err := getCount(bson.M{"data_type": 3008})
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	resp.ApplicationCount = applicationCount
	crontabCount, err := getCount(bson.M{"data_type": 2001})
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	resp.CrontabCount = crontabCount
	kmodCount, err := getCount(bson.M{"data_type": 2001})
	if err != nil {
		common.Response(c, common.ErrorCode, err.Error())
		return
	}
	resp.KmodCount = kmodCount

	common.Response(c, common.SuccessCode, &resp)
}

func getCount(filter bson.M) (int64, error) {
	var max int64 = countLimit
	opts := &options.CountOptions{
		Limit: &max,
	}
	return mongo.MongoProxyImpl.AssetC.CountDocuments(context.Background(), filter, opts)
}
