BINARY_LINUX64=dist/token_auth-linux-amd64
SOURCE=$(shell find . -name "*go" -a -not -path "./vendor/*" -not -path "./cmd/testgen/*" )
VERSION=$(shell git describe --tags)

.PHONY: assets test lint build clean

lint:
	golangci-lint run ./...
	golint ./...
test:
	go test -v ./...
coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

build:
	cd mock && go generate && cd ..
	cd cmd && GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags \
				"-s -w" -o ../$(BINARY_LINUX64)

assets: build
	mkdir -p assets
	zip assets/token_auth-${VERSION}-linux-amd64.zip $(BINARY_LINUX64) README.md
	tar czf assets/token_auth-${VERSION}-linux-amd64.tgz $(BINARY_LINUX64) README.md
	sha256sum assets/token_auth-* > assets/SHASUMS256.txt