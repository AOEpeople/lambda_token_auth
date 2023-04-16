package main

import (
	"github.com/aws/aws-lambda-go/lambda"
	log "github.com/sirupsen/logrus"
	"os"
	"strconv"
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
		log.Infof("CONFIG_BUCKET or CONFIG_KEY empty")
	}

	roleAnnotationsEnabled, err := strconv.ParseBool(os.Getenv("CONFIG_ROLEANNOTATIONSENABLED"))
	if err != nil {
		roleAnnotationsEnabled = false
	}

	config := &auth.Config{
		Bucket:                 bucket,
		ObjectKey:              key,
		JwksURL:                os.Getenv("CONFIG_JWKSURL"),
		Region:                 os.Getenv("CONFIG_REGION"),
		Duration:               3600,
		RoleAnnotationsEnabled: roleAnnotationsEnabled,
		RoleAnnotationPrefix:   "token_auth/",
		BoundIssuer:            os.Getenv("CONFIG_BOUND_ISSUER"),
		BoundAudience:          os.Getenv("CONFIG_BOUND_AUDIENCE"),
	}

	awsConsumer, err = auth.NewAwsConsumer(config)
	if err != nil {
		log.Fatalf("Error initializing: %v", err)
	}
	tokenValidator = auth.NewTokenValidator(awsConsumer.JwksURL(), awsConsumer.BoundIssuer(), awsConsumer.BoundAudience())
}

func main() {
	authHandler := auth.NewHandler(awsConsumer, tokenValidator)
	lambda.Start(authHandler)
}
