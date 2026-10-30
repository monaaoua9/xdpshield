VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BIN     := bin/xdpshield
GOFLAGS := -trimpath -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: all build generate test test-unit test-integration vet lint lab clean

all: build

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -o $(BIN) ./cmd/xdpshield
	CGO_ENABLED=0 go build $(GOFLAGS) -o bin/xdpshieldctl ./cmd/xdpshieldctl

# needs clang + llvm-strip + libbpf headers (apt install clang llvm libbpf-dev linux-libc-dev)
generate:
	go generate ./internal/dataplane/

test: test-unit

test-unit:
	go test -race ./...

# runs the real bpf program with BPF_PROG_TEST_RUN, needs root and linux >= 5.8
test-integration:
	go test -c -tags integration -o bin/dataplane.test ./internal/dataplane/
	sudo ./bin/dataplane.test -test.v

vet:
	go vet ./...
	GOOS=linux go vet ./...

lint: vet
	@test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

# veth + netns lab, see test/lab.sh
lab:
	sudo test/lab.sh up

clean:
	rm -rf bin
