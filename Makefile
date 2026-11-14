SHELL := /bin/bash
BIN   := keybaton
VER   ?= 0.1.0
LDFLAGS := -s -w -X main.version=$(VER)

.PHONY: build test vet fmt cross clean docker

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/$(BIN) ./cmd/keybaton

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal

# 纯 Go SQLite，交叉编译不需要 C 工具链
cross:
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o bin/$(BIN)-darwin-arm64  ./cmd/keybaton
	CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/$(BIN)-darwin-amd64  ./cmd/keybaton
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o bin/$(BIN)-linux-amd64   ./cmd/keybaton
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o bin/$(BIN)-linux-arm64   ./cmd/keybaton
	@ls -lh bin/

docker:
	docker build -t keybaton:$(VER) .

clean:
	rm -rf bin
