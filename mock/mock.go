//go:generate mockgen -package=mock -source=../authorization_handler.go -destination=authorization_handler.go
//go:generate mockgen -package=mock -source=../aws_consumer.go -destination=aws_consumer.go
//go:generate mockgen -package=mock -source=../token_validator.go -destination=token_validator.go

package mock