package main

import (
	"github.com/aws/aws-lambda-go/lambda"
	"log"
	"os"
	auth "token_authorizer"
)

var gitlabAuthorizationHandler *auth.GitlabAuthorizer
func init() {

	bucket := os.Getenv("CONFIG_BUCKET")
	key := os.Getenv("CONFIG_KEY")
	if bucket == "" || key == "" {
		log.Fatalf("CONFIG_BUCKET or CONFIG_KEY empty")
	}

	var err error
	gitlabAuthorizationHandler, err = auth.NewGitlabAuthorizationHandler(bucket, key)
	if err != nil {
		log.Fatalf("Error initializing: %v", err)
	}
}

func main() {
	authHandler := auth.NewHandler(gitlabAuthorizationHandler)
	lambda.Start(authHandler)
}
