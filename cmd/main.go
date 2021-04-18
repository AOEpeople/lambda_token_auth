package main

import (
	"context"
	"fmt"
	"github.com/aws/aws-lambda-go/lambda"
	"log"
	"net/http"
	"os"
	auth"token_authorizer"
)

var config *auth.Config
var awsConsumer *auth.AwsConsumer
var tokenValidator *auth.TokenValidator
var _testing = false

func init() {
	if _testing {
		return
	}
	bucket := os.Getenv("CONFIG_BUCKET")
	key := os.Getenv("CONFIG_KEY")
	if bucket == "" || key == "" {
		log.Fatalf("CONFIG_BUCKET or CONFIG_KEY empty")
	}

	config = &auth.Config{}
	err := awsConsumer.ReadConfiguration(config, bucket, key)
	if err != nil {
		log.Fatalf("Error reading configuration: %v", err)
	}
	if len(config.Rules) <= 0 {
		log.Fatalf("Empty rules configuration found")
	}

	tokenValidator = auth.NewTokenValidator(config.JwksUrl)
}

func HandleRequest(ctx context.Context, event auth.HandleEvent) (auth.HandleResponse, error) {

	log.Printf("Retrieved HandleEvent for Role %s\n%s", event.Query.Role, event.Headers.Authorization)

	claims, err := tokenValidator.RetrieveClaimsFromToken(event.Headers.Authorization)
	if err != nil {
		return auth.RespondError(err, http.StatusUnauthorized)
	}

	log.Printf("Validated Token")

	role, err := tokenValidator.ValidateClaimsForRule(claims, event.Query.Role, config.Rules)
	if err != nil {
		return auth.RespondError(err, http.StatusInternalServerError)
	} else if role == nil {
		return auth.RespondError(fmt.Errorf("unable to find matching role for the given token"), http.StatusUnauthorized)
	}

	log.Printf("Retrieved request from %s to assume role %s", claims.UserLogin, role.Role)
	credentials, err := awsConsumer.AssumeRole(role, claims.UserLogin)
	if err != nil {
		return auth.RespondError(err, http.StatusInternalServerError)
	}

	if event.Headers.Accept == "text/x-shellscript" {
		return auth.RespondShellscript(credentials)
	}

	return auth.RespondJson(credentials)
}

func main() {
	lambda.Start(HandleRequest)
}
