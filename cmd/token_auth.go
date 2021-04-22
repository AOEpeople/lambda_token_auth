package main

import (
	"github.com/aws/aws-lambda-go/lambda"
	log "github.com/sirupsen/logrus"
	"os"
	auth "token_authorizer"
)

var jwtAuthorizer *auth.JWTAuthorizer

func init() {
	loglevel := os.Getenv("LOGLEVEL")
	log.SetFormatter(&log.JSONFormatter{})
	level, err := log.ParseLevel(loglevel)
	if err != nil {
		level = log.WarnLevel
	}
	log.SetLevel(level)

	bucket := os.Getenv("CONFIG_BUCKET")
	key := os.Getenv("CONFIG_KEY")
	if bucket == "" || key == "" {
		log.Fatalf("CONFIG_BUCKET or CONFIG_KEY empty")
	}

	jwtAuthorizer, err = auth.NewJWTAuthorizationHandler(bucket, key)
	if err != nil {
		log.Fatalf("Error initializing: %v", err)
	}
}

func main() {
	authHandler := auth.NewHandler(jwtAuthorizer)
	lambda.Start(authHandler)
}
