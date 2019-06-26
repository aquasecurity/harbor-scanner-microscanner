# microscaner-proxy

```
$ GOOS=linux go build -o bin/microscanner-proxy cmd/microscanner-proxy.go
$ docker build -t aquasec/microscanner-proxy:latest .
$ docker run --name microscanner-proxy --rm -d -p 8080:8080 aquasec/microscanner-proxy
```

```
eval $(minikube docker-env -p harbor)
```