//go:generate mockgen -package=mock -source=../authorizer.go -destination=authorizer.go
//go:generate mockgen -package=mock -source=../aws_consumer.go -destination=aws_consumer.go
//go:generate mockgen -package=mock -source=../token_validator.go -destination=token_validator.go

package mock