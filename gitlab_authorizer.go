package auth

import (
	"fmt"
)

// GitlabAuthorizer allows to perform authorization with tokes coming from Gitlab instances
type GitlabAuthorizer struct {
	config *Config
	awsConsumer *AwsConsumer
	tokenValidator *TokenValidator
}

// NewGitlabAuthorizationHandler instantiates a GitlabAuthorizer
func NewGitlabAuthorizationHandler(bucket, key string) (*GitlabAuthorizer, error) {
	authHandler := GitlabAuthorizer{}
	authHandler.awsConsumer = &AwsConsumer{}
	authHandler.config = &Config{}

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
func (h *GitlabAuthorizer) TokenValidator() TokenValidatorInterface {
	return h.tokenValidator
}

// AwsConsumer ...
func (h *GitlabAuthorizer) AwsConsumer() AwsConsumerInterface {
	return h.awsConsumer
}
// Config ...
func (h *GitlabAuthorizer) Config() *Config {
	return h.config
}
