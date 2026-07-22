.PHONY: app build release test test-race vet

build:
	mkdir -p bin
	GOCACHE=$${GOCACHE:-/tmp/yubitouch-gocache} go build -buildvcs=false -o bin/yubitouch ./cmd/yubitouch
	GOCACHE=$${GOCACHE:-/tmp/yubitouch-gocache} go build -buildvcs=false -o bin/age-plugin-yubitouch ./cmd/age-plugin-yubitouch
	@if [ "$$(uname -s)" = Darwin ]; then \
		codesign --force --options runtime --entitlements packaging/YubiTouch.entitlements --sign - bin/yubitouch; \
		codesign --force --options runtime --sign - bin/age-plugin-yubitouch; \
		codesign --verify --strict bin/yubitouch; \
		codesign --verify --strict bin/age-plugin-yubitouch; \
	fi

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
