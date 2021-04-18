go mod tidy
GOOS=linux CGO_ENABLED=0 GOARCH=amd64 go build -o dist/main cmd/main.go
zip dist/function.zip dist/main
cp dist/function.zip ../Team/terraform/stacks/000_token_auth/src