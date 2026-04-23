.PHONY: build test release clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS = -ldflags "-X main.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o envguard .

test:
	go test ./...

release:
	GOOS=darwin  GOARCH=amd64  go build $(LDFLAGS) -o dist/envguard-darwin-amd64 .
	GOOS=darwin  GOARCH=arm64  go build $(LDFLAGS) -o dist/envguard-darwin-arm64 .
	GOOS=linux   GOARCH=amd64  go build $(LDFLAGS) -o dist/envguard-linux-amd64 .
	GOOS=linux   GOARCH=arm64  go build $(LDFLAGS) -o dist/envguard-linux-arm64 .

clean:
	rm -f envguard dist/envguard-*
