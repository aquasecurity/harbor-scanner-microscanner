SOURCES := $(shell find . -name '*.go')
BINARY := microscanner-proxy
IMAGE := aquasec/microscanner-proxy:latest

build: microscanner-proxy

$(BINARY): $(SOURCES)
	GOOS=linux GO111MODULE=on CGO_ENABLED=0 go build -o bin/$(BINARY) cmd/microscanner-proxy.go

container: build
	docker build -t $(IMAGE) .

container-run: container
	docker run --name microscanner-proxy --rm -d -p 8080:8080 $(IMAGE)