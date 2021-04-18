package token_authorizer

import (
	"context"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"net/http"
)

type AuthorizationHandler interface {}

// see https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-integrations-lambda.html
type HandleResponse struct {
	IsBase64Encoded bool `json:"isBase64Encoded,omitempty"`
	StatusCode      int  `json:"statusCode,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Body string `json:"body,omitempty"`
}

type HandleEvent struct {
	Headers struct {
		Authorization string `json:"authorization"`
		Accept        string `json:"accept"`
	} `json:"headers"`

	Query struct {
		Role string `json:"role"`
	} `json:"queryStringParameters"`
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

type Handler func(ctx context.Context, event HandleEvent) (HandleResponse, error)

func NewHandler(auth AuthorizationHandler) Handler {
	return func(ctx context.Context, event HandleEvent) (HandleResponse, error) {
		return RespondError(fmt.Errorf("Invalid arguments."), http.StatusInternalServerError)
	}
}