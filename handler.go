package auth

import (
	"context"
	"fmt"
	"log"
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
	Accept        string `json:"accept"`
}

// EventQuery all query fields we expect in a request
type EventQuery struct {
	Role string `json:"role"`
}

// Claims all claim fields a token from Gitlab could have
type Claims struct {
	ClaimsJson []byte
	jwt.StandardClaims
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
	Role        string `json:"role"`
	Region      string `json:"region"`
	Duration    int64  `json:"duration"`
	ClaimValues Claims `json:"claim_values"`
}

// Handler lambda function interface
type Handler func(ctx context.Context, event Event) (HandlerResponse, error)

// NewHandler creates the actual Handler function
func NewHandler(auth Authorizer) Handler {
	return func(ctx context.Context, event Event) (HandlerResponse, error) {

		if event.Headers.Authorization == "" || event.Query.Role == "" {
			return RespondError(fmt.Errorf("invalid arguments"), http.StatusBadRequest)
		}

		if !auth.AwsConsumer().ValidateRole(event.Query.Role) {
			return RespondError(fmt.Errorf("invalid IAM role ARN"), http.StatusBadRequest)
		}

		log.Printf("Retrieved Event for Role %s\n%s", event.Query.Role, event.Headers.Authorization)

		claims, err := auth.TokenValidator().RetrieveClaimsFromToken(event.Headers.Authorization)
		if err != nil {
			return RespondError(err, http.StatusUnauthorized)
		}

		log.Printf("Validated Token")

		role, err := auth.TokenValidator().ValidateClaimsForRule(claims, event.Query.Role, auth.Config().Rules)
		if err != nil {
			return RespondError(err, http.StatusInternalServerError)
		} else if role == nil {
			return RespondError(fmt.Errorf("unable to find matching role for the given token"), http.StatusUnauthorized)
		}

		log.Printf("Retrieved request from %s to assume role %s", claims.Subject, role.Role)
		credentials, err := auth.AwsConsumer().AssumeRole(role, claims.Subject)
		if err != nil {
			return RespondError(err, http.StatusInternalServerError)
		}

		if event.Headers.Accept == "text/x-shellscript" {
			return RespondShellscript(credentials)
		}

		return RespondJSON(credentials)
	}
}
