package token_authorizer

import (
	"context"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
)

type Event struct {
	Headers EventHeaders `json:"headers"`
	Query   EventQuery   `json:"queryStringParameters"`
}
type EventHeaders struct {
	Authorization string `json:"authorization"`
	Accept        string `json:"accept"`
}
type EventQuery struct {
	Role string `json:"role"`
}

type GitlabClaims struct {
	NamespaceId          string `json:"namespace_id,omitempty"`
	NamespacePath        string `json:"namespace_path,omitempty"`
	ProjectId            string `json:"project_id,omitempty"`
	ProjectPath          string `json:"project_path,omitempty"`
	UserId               string `json:"user_id,omitempty"`
	UserLogin            string `json:"user_login,omitempty"`
	UserEmail            string `json:"user_email,omitempty"`
	PipelineId           string `json:"pipeline_id,omitempty"`
	JobId                string `json:"job_id,omitempty"`
	Environment          string `json:"environment,omitempty"`
	EnvironmentProtected string `json:"environment_protected,omitempty"`
	jwt.StandardClaims
}

type Config struct {
	JwksUrl  string `json:"jwks_url"`
	Region   string `json:"region"`
	Duration int64  `json:"duration"`
	Rules    []Rule `json:"rules"`
}
type Rule struct {
	Role        string       `json:"role"`
	Region      string       `json:"region"`
	Duration    int64        `json:"duration"`
	ClaimValues GitlabClaims `json:"claim_values"`
}

type Handler func(ctx context.Context, event Event) (HandlerResponse, error)

func NewHandler(auth Authorizer) Handler {
	return func(ctx context.Context, event Event) (HandlerResponse, error) {

		if event.Headers.Authorization == "" || event.Query.Role == "" {
			return RespondError(fmt.Errorf("invalid arguments"), http.StatusBadRequest)
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

		log.Printf("Retrieved request from %s to assume role %s", claims.UserLogin, role.Role)
		credentials, err := auth.AwsConsumer().AssumeRole(role, claims.UserLogin)
		if err != nil {
			return RespondError(err, http.StatusInternalServerError)
		}

		if event.Headers.Accept == "text/x-shellscript" {
			return RespondShellscript(credentials)
		}

		return RespondJson(credentials)
	}
}
