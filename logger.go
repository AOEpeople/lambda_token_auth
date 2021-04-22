package auth

import (
	"context"
	log "github.com/sirupsen/logrus"
)

func Logger(ctx context.Context) *log.Entry {
	logger := log.WithFields(log.Fields{})
	if ctx == nil {
		return logger
	}
	if ctxRqId, ok := ctx.Value(requestIdKey).(string); ok {
		logger = log.WithFields(log.Fields{
			"request-id": ctxRqId,
		})
	}
	return logger
}