package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/golang-jwt/jwt/v5"
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
}

// EventQuery all query fields we expect in a request
type EventQuery struct {
	Role string `json:"role"`
}

// Claims all claim fields a token from Gitlab could have
type Claims struct {
	ClaimsJSON       []byte
	RegisteredClaims *jwt.RegisteredClaims
}

// Rule represents a single claim to role mapping
type Rule struct {
	Role        string          `json:"role"`
	Region      string          `json:"region"`
	Duration    int64           `json:"duration"`
	ClaimValues json.RawMessage `json:"claim_values"`
}

// Handler lambda function interface
type Handler func(ctx context.Context, event Event) (HandlerResponse, error)

// NewHandler creates the actual Handler function
func NewHandler(consumer AwsConsumerInterface, validator TokenValidatorInterface) Handler {
	return func(ctx context.Context, event Event) (HandlerResponse, error) {
		logger := Logger(ctx)

		if event.Headers.Authorization == "" || event.Query.Role == "" {
			return RespondError(ctx, fmt.Errorf("invalid arguments"), http.StatusBadRequest)
		}

		iamRules, err := consumer.RetrieveRulesFromRoleTags(ctx, event.Query.Role)
		if err != nil {
			return RespondError(ctx, err, http.StatusBadRequest)
		}
		logger.Infof("Retrieved Event for Role %s\n%s", event.Query.Role, event.Headers.Authorization)

		rules := append(consumer.Rules(), iamRules...)
		claims, err := validator.RetrieveClaimsFromToken(ctx, event.Headers.Authorization)
		if err != nil {
			return RespondError(ctx, err, http.StatusUnauthorized)
		}
		logger.Debugf("Claims JSON: %s", claims.ClaimsJSON)
		logger.Infof("Validated Token")

		role, err := validator.ValidateClaimsForRule(ctx, claims, event.Query.Role, rules)
		if err != nil {
			return RespondError(ctx, err, http.StatusInternalServerError)
		} else if role == nil {
			return RespondError(ctx, fmt.Errorf("unable to find matching role for the given token"), http.StatusUnauthorized)
		}

		logger.Infof("Retrieved request from %s to assume role %s", claims.RegisteredClaims.Subject, role.Role)
		credentials, err := consumer.AssumeRole(ctx, role, claims.RegisteredClaims.Subject)
		if err != nil {
			return RespondError(ctx, err, http.StatusInternalServerError)
		}

		if event.Headers.Accept == "text/x-shellscript" {
			return RespondShellscript(ctx, credentials)
		}

		return RespondJSON(ctx, credentials)
	}
}
