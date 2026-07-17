.PHONY: app build test test-race vet

build:
	mkdir -p bin
	GOCACHE=$${GOCACHE:-/tmp/yubitouch-gocache} go build -o bin/yubitouch ./cmd/yubitouch

app:
	./scripts/build-app.sh

test:
	GOCACHE=$${GOCACHE:-/tmp/yubitouch-gocache} go test ./...

test-race:
	GOCACHE=$${GOCACHE:-/tmp/yubitouch-gocache} go test -race ./...

vet:
	GOCACHE=$${GOCACHE:-/tmp/yubitouch-gocache} go vet ./...
