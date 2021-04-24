package auth

import (
	"fmt"
)

// JWTAuthorizer allows to perform authorization with tokes coming from Gitlab instances
type JWTAuthorizer struct {
	config         *Config
	awsConsumer    *AwsConsumer
	tokenValidator *TokenValidator
}

// NewJWTAuthorizationHandler instantiates a JWTAuthorizer
func NewJWTAuthorizationHandler(bucket, key string) (*JWTAuthorizer, error) {
	config := &Config{
		Duration: 3600,
		EnableRoleAnnotations: false,
	}

	authHandler := JWTAuthorizer{}
	authHandler.awsConsumer = NewAwsConsumer(config)
	authHandler.config = config

	err := authHandler.awsConsumer.ReadConfiguration(authHandler.config, bucket, key)
	if err != nil {
		return nil, fmt.Errorf("error reading configuration: %v", err)
	}
	if len(authHandler.config.Rules) <= 0 {
		return nil, fmt.Errorf("empty rules configuration found")
	}

	authHandler.tokenValidator = NewTokenValidator(authHandler.config.JwksURL)
	return &authHandler, nil
}

// TokenValidator ...
func (h *JWTAuthorizer) TokenValidator() TokenValidatorInterface {
	return h.tokenValidator
}

// AwsConsumer ...
func (h *JWTAuthorizer) AwsConsumer() AwsConsumerInterface {
	return h.awsConsumer
}

// Config ...
func (h *JWTAuthorizer) Config() *Config {
	return h.config
}
