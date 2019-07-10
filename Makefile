SOURCES := $(shell find . -name '*.go')
BINARY := microscanner-adapter
IMAGE := aquasec/harbor-microscanner-adapter:poc

build: $(BINARY)

$(BINARY): $(SOURCES)
	GOOS=linux GO111MODULE=on CGO_ENABLED=0 go build -o bin/$(BINARY) cmd/microscanner-adapter.go

container: build
	docker build -t $(IMAGE) .

container-run: container
	docker run --name microscanner-adapter --rm -d -p 8080:8080 $(IMAGE)