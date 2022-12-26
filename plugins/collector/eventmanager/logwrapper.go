package eventmanager

import (
	"github.com/robfig/cron/v3"
	"go.uber.org/zap"
)

var _ cron.Logger = (*logWrapper)(nil)

// An internal wrapper of zap logger
type logWrapper struct {
	logger *zap.Logger
}

func (l *logWrapper) Info(msg string, keysAndValues ...interface{}) {
	l.logger.Info(msg, zap.Any("data", keysAndValues))
}
func (l *logWrapper) Error(err error, msg string, keysAndValues ...interface{}) {
	l.logger.Error(msg, zap.Any("data", keysAndValues), zap.Any("error", err))
}
