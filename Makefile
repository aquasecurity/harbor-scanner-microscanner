SOURCES := $(shell find . -name '*.go')
BINARY := scanner-microscanner
IMAGE_TAG := poc
IMAGE := danielpacak/harbor-scanner-microscanner:$(IMAGE_TAG)

build: $(BINARY)

test: build
	GO111MODULE=on go test -v -short ./...

test-integration: build
	GO111MODULE=on go test -v ./...

$(BINARY): $(SOURCES)
	GOOS=linux GO111MODULE=on CGO_ENABLED=0 go build -o bin/$(BINARY) cmd/scanner-microscanner/main.go

container: build
	docker build -t $(IMAGE) .

compose-up: container
	docker-compose -f compose/docker-compose.yaml -p microscanner up -d

compose-down:
	docker-compose -f compose/docker-compose.yaml -p microscanner down