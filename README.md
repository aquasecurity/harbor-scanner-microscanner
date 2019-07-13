# harbor-microscanner-adapter

```
$ eval $(minikube docker-env -p harbor)
$ make container
$ kubectl -n harbor apply -f kube/harbor-microscanner-adapter.yaml
```

## TODO

- [ ] Configurable cacheDir (`/tmp/docker`) instead of using dataFile
- [ ] Configurable path to microscanner's executable

https://medium.com/hootsuite-engineering/building-docker-images-inside-kubernetes-42c6af855f25
