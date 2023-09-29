BUILD_DIR=dist
BINARY_LINUX64=bootstrap # fixed name for provided.al2 runtime
SOURCE=$(shell find . -name "*go" -a -not -path "./vendor/*" -not -path "./cmd/testgen/*" )
VERSION=$(shell git describe --tags)

.PHONY: assets test lint build clean coverage generate

lint:
	golangci-lint run ./...
	golint ./...
test:
	go test -v ./...

coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out

generate:
	cd mock; go generate ; cd ..

build:
	mkdir -p $(BUILD_DIR)
	cd cmd && GO111MODULE=on CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags lambda.norpc -ldflags \
				"-s -w" -o ../$(BUILD_DIR)/$(BINARY_LINUX64)

assets: build
	mkdir -p assets
	cp README.md $(BUILD_DIR)/README.md

	cd $(BUILD_DIR); zip ../assets/token_auth-${VERSION}-linux-amd64.zip $(BINARY_LINUX64) README.md
	cd $(BUILD_DIR); tar czf ../assets/token_auth-${VERSION}-linux-amd64.tgz $(BINARY_LINUX64) README.md

	sha256sum assets/token_auth-* > assets/SHASUMS256.txt