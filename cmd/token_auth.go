package main

import (
	"github.com/aws/aws-lambda-go/lambda"
	log "github.com/sirupsen/logrus"
	"os"
	auth "token_authorizer"
)

var awsConsumer *auth.AwsConsumer
var tokenValidator *auth.TokenValidator

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

	config := &auth.Config{
		Bucket:                bucket,
		ObjectKey:             key,
		Duration:              3600,
		EnableRoleAnnotations: false,
	}

	awsConsumer, err := auth.NewAwsConsumer(config)
	if err != nil {
		log.Fatalf("Error initializing: %v", err)
	}
	tokenValidator = auth.NewTokenValidator(awsConsumer.JwksUrl())
}

func main() {
	authHandler := auth.NewHandler(awsConsumer, tokenValidator)
	lambda.Start(authHandler)
}
