.PHONY: app build release test test-race vet

build:
	mkdir -p bin
	GOCACHE=$${GOCACHE:-/tmp/yubitouch-gocache} go build -buildvcs=false -o bin/yubitouch ./cmd/yubitouch

app:
	./scripts/build-app.sh

release:
	@test -n "$(VERSION)" || (echo "VERSION is required, for example VERSION=0.1.0" >&2; exit 2)
	VERSION="$(VERSION)" ./scripts/release.sh "$(VERSION)"

test:
	GOCACHE=$${GOCACHE:-/tmp/yubitouch-gocache} go test ./...

test-race:
	GOCACHE=$${GOCACHE:-/tmp/yubitouch-gocache} go test -race ./...

vet:
	GOCACHE=$${GOCACHE:-/tmp/yubitouch-gocache} go vet ./...
