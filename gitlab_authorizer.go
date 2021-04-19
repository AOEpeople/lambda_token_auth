package lambda_token_auth

import (
	"fmt"
)

type GitlabAuthorizer struct {
	config *Config
	awsConsumer *AwsConsumer
	tokenValidator *TokenValidator
}

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

	authHandler.tokenValidator = NewTokenValidator(authHandler.config.JwksUrl)
	return &authHandler, nil
}

func (h *GitlabAuthorizer) TokenValidator() TokenValidatorInterface {
	return h.tokenValidator
}
func (h *GitlabAuthorizer) AwsConsumer() AwsConsumerInterface {
	return h.awsConsumer
}
func (h *GitlabAuthorizer) Config() *Config {
	return h.config
}
