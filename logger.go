package auth

import (
	"context"
	log "github.com/sirupsen/logrus"
)

// Logger creates a logger with additional fields taken from the context
func Logger(ctx context.Context) *log.Entry {
	logger := log.WithFields(log.Fields{})
	if ctx == nil {
		return logger
	}
	if ctxRqID, ok := ctx.Value("awsRequestId").(string); ok {
		logger = log.WithFields(log.Fields{
			"request-id": ctxRqID,
		})
	}
	return logger
}
