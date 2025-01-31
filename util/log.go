package util

import (
	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
)

func LogNew() logr.Logger {
	config := zap.NewProductionConfig()

	logger, err := config.Build()
	if err != nil {
		panic(err)
	}
	defer logger.Sync() // flushes buffer, if any
	return zapr.NewLogger(logger)
}
