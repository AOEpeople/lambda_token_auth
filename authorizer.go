package auth

// Authorizer acts as a controller for the Handler flow
type Authorizer interface {
	TokenValidator() TokenValidatorInterface
	AwsConsumer() AwsConsumerInterface
	Config() *Config
}