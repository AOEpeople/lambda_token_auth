package lambda_token_auth

type Authorizer interface {
	TokenValidator() TokenValidatorInterface
	AwsConsumer() AwsConsumerInterface
	Config() *Config
}