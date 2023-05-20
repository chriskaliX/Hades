package basic

import (
	"hboat/pkg/basic/mongo"
	"hboat/pkg/basic/redis"
	"hboat/pkg/conf"
	"strconv"
	"time"

	lumberjack "gopkg.in/natefinch/lumberjack.v2"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Initialization of the whole package program
func Initialization() error {
	initLog()
	// init the datasources
	if err := mongo.MongoProxyImpl.Init(conf.Config.Mongo.URI, conf.Config.Mongo.PoolSize); err != nil {
		return err
	}
	if err := redis.RedisProxyImpl.Init(
		conf.Config.Redis.Addrs,
		conf.Config.Redis.MasterName,
		conf.Config.Redis.Password,
		redis.RedisMode(conf.Config.Redis.Mode)); err != nil {
		return err
	}
	return nil
}

func initLog() {
	config := zap.NewProductionEncoderConfig()
	config.CallerKey = "source"
	config.TimeKey = "timestamp"
	config.EncodeTime = func(t time.Time, z zapcore.PrimitiveArrayEncoder) {
		z.AppendString(strconv.FormatInt(t.Unix(), 10))
	}
	fileEncoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	fileWriter := zapcore.AddSync(&lumberjack.Logger{
		Filename:   "hboat.log",
		MaxSize:    1,
		MaxBackups: 10,
		MaxAge:     10,   // days
		Compress:   true, // disabled by default
	})
	core := zapcore.NewTee(
		zapcore.NewCore(fileEncoder, fileWriter, zap.InfoLevel))
	logger := zap.New(core, zap.AddCaller())
	defer logger.Sync()
	zap.ReplaceGlobals(logger)
}
