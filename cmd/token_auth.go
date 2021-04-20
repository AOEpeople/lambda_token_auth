package main

import (
	"github.com/aws/aws-lambda-go/lambda"
	"log"
	"os"
	auth "token_authorizer"
)

var jwtAuthorizer *auth.JWTAuthorizer

func init() {

	bucket := os.Getenv("CONFIG_BUCKET")
	key := os.Getenv("CONFIG_KEY")
	if bucket == "" || key == "" {
		log.Fatalf("CONFIG_BUCKET or CONFIG_KEY empty")
	}

	var err error
	jwtAuthorizer, err = auth.NewJWTAuthorizationHandler(bucket, key)
	if err != nil {
		log.Fatalf("Error initializing: %v", err)
	}
}

func main() {
	authHandler := auth.NewHandler(jwtAuthorizer)
	lambda.Start(authHandler)
}
