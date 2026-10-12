.PHONY: build clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

compile:
	@echo "C bytecode modules are compiled in modules repo"

build:
	CGO_ENABLED=0 go build -ldflags "-s -w -X main.version=$(VERSION)" -o eprobe ./cmd/eprobe

clean:
	rm -f eprobe
