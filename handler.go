package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/dgrijalva/jwt-go"
)

// Event all data we expect within a request
type Event struct {
	Headers EventHeaders `json:"headers"`
	Query   EventQuery   `json:"queryStringParameters"`
}

// EventHeaders all header fields we expect in a request
type EventHeaders struct {
	Authorization string `json:"authorization"`
	Accept        string `json:"accept,omitempty"`
	AmznRequestId string `json:"x-amzn-RequestId,omitempty"`
}

// EventQuery all query fields we expect in a request
type EventQuery struct {
	Role string `json:"role"`
}

// Claims all claim fields a token from Gitlab could have
type Claims struct {
	ClaimsJSON     []byte
	StandardClaims *jwt.StandardClaims
}

// Config holds all configuration for the Handler
type Config struct {
	JwksURL  string `json:"jwks_url"`
	Region   string `json:"region"`
	Duration int64  `json:"duration"`
	Rules    []Rule `json:"rules"`
}

// Rule represents a single claim to role mapping
type Rule struct {
	Role        string          `json:"role"`
	Region      string          `json:"region"`
	Duration    int64           `json:"duration"`
	ClaimValues json.RawMessage `json:"claim_values"`
}

type correlationIdType int
const (
	requestIdKey correlationIdType = iota
)
// Handler lambda function interface
type Handler func(ctx context.Context, event Event) (HandlerResponse, error)

// NewHandler creates the actual Handler function
func NewHandler(auth Authorizer) Handler {
	return func(ctx context.Context, event Event) (HandlerResponse, error) {
		context.WithValue(ctx,requestIdKey, event.Headers.AmznRequestId)
		logger := Logger(ctx)

		if event.Headers.Authorization == "" || event.Query.Role == "" {
			return RespondError(ctx, fmt.Errorf("invalid arguments"), http.StatusBadRequest)
		}

		if !auth.AwsConsumer().ValidateRole(event.Query.Role) {
			return RespondError(ctx, fmt.Errorf("invalid IAM role ARN"), http.StatusBadRequest)
		}

		logger.Infof("Retrieved Event for Role %s\n%s", event.Query.Role, event.Headers.Authorization)

		claims, err := auth.TokenValidator().RetrieveClaimsFromToken(ctx, event.Headers.Authorization)
		if err != nil {
			return RespondError(ctx, err, http.StatusUnauthorized)
		}
		logger.Debugf("Claims JSON: %s", claims.ClaimsJSON)
		logger.Infof("Validated Token")

		role, err := auth.TokenValidator().ValidateClaimsForRule(ctx, claims, event.Query.Role, auth.Config().Rules)
		if err != nil {
			return RespondError(ctx, err, http.StatusInternalServerError)
		} else if role == nil {
			return RespondError(ctx, fmt.Errorf("unable to find matching role for the given token"), http.StatusUnauthorized)
		}

		logger.Infof("Retrieved request from %s to assume role %s", claims.StandardClaims.Subject, role.Role)
		credentials, err := auth.AwsConsumer().AssumeRole(role, claims.StandardClaims.Subject)
		if err != nil {
			return RespondError(ctx, err, http.StatusInternalServerError)
		}

		if event.Headers.Accept == "text/x-shellscript" {
			return RespondShellscript(ctx, credentials)
		}

		return RespondJSON(ctx, credentials)
	}
}
