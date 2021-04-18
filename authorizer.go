package token_authorizer

type Authorizer interface {
	TokenValidator() TokenValidatorInterface
	AwsConsumer() AwsConsumerInterface
	Config() *Config
}