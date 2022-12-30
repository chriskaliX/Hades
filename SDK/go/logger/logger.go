// The logger, we have to sync with elkeid since the compatibility
// purpose.
package logger

import (
	"strconv"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/chriskaliX/SDK/clock"
	"github.com/chriskaliX/SDK/transport/client"
)

type Config struct {
	// SDK fields
	Client *client.Client
	Clock  clock.IClock

	Path        string
	MaxSize     int
	MaxBackups  int
	Compress    bool
	FileLevel   zapcore.LevelEnabler
	RemoteLevel zapcore.LevelEnabler
}

func New(config *Config) *zap.Logger {
	var l *zap.Logger
	remoteConfig := zap.NewProductionEncoderConfig()
	remoteConfig.CallerKey = "source"
	remoteConfig.TimeKey = "timestamp"
	remoteConfig.EncodeTime = func(t time.Time, z zapcore.PrimitiveArrayEncoder) {
		z.AppendString(strconv.FormatInt(t.Unix(), 10))
	}
	// sync to remote(agent) configuration
	remoteEncoder := zapcore.NewJSONEncoder(remoteConfig)
	remoteWriter := &remoteWriter{
		client: config.Client,
		clock:  config.Clock,
	}
	fileEncoder := zapcore.NewConsoleEncoder(zap.NewDevelopmentEncoderConfig())
	fileWriter := zapcore.AddSync(&lumberjack.Logger{
		Filename:   config.Path,
		MaxSize:    config.MaxSize, // megabytes
		MaxBackups: config.MaxBackups,
		Compress:   config.Compress, // disabled by default
	})
	core := zapcore.NewTee(
		zapcore.NewSamplerWithOptions(
			zapcore.NewCore(remoteEncoder, remoteWriter, config.RemoteLevel), time.Second, 4, 1),
		zapcore.NewSamplerWithOptions(
			zapcore.NewCore(fileEncoder, fileWriter, config.FileLevel), time.Second, 4, 1),
	)
	l = zap.New(core, zap.AddCaller())
	zap.ReplaceGlobals(l)
	return l
}
