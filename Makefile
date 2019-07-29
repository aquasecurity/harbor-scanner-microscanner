SOURCES := $(shell find . -name '*.go')
BINARY := scanner-microscanner
IMAGE_TAG := poc
IMAGE := danielpacak/harbor-scanner-microscanner:$(IMAGE_TAG)

build: $(BINARY)

$(BINARY): $(SOURCES)
	GOOS=linux GO111MODULE=on CGO_ENABLED=0 go build -o bin/$(BINARY) cmd/scanner-microscanner/main.go

container: build
	docker build -t $(IMAGE) .
