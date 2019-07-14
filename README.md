# harbor-microscanner-adapter

```
eval $(minikube docker-env -p harbor)

make container

MICROSCANNER_TOKEN="TOKENGOESHERE"
kubectl create secret generic harbor-microscanner-adapter \
  --from-literal="microscanner-token=${MICROSCANNER_TOKEN}"

kubectl -n harbor apply -f kube/harbor-microscanner-adapter.yaml
```

```
# Check harbor-microscanner-adapter pod name
MICROSCANNER_ADAPTER_POD=harbor-microscanner-adapter-f49f79775-9bdtm

kubectl exec ${MICROSCANNER_ADAPTER_POD} -c dind \
  -- mkdir -p /etc/docker/certs.d/core.harbor.domain
kubectl cp ~/Downloads/ca.crt \
  ${MICROSCANNER_ADAPTER_POD}:/etc/docker/certs.d/core.harbor.domain -c dind

DOCKER_HOST=tcp://localhost:2375 docker pull core.harbor.domain/library/mongo:3.4.21-xenial
```

```
kubectl port-forward service/harbor-microscanner-adapter 8080:8080 > /dev/null &
curl -H http://localhost:8080/api/v1/
```

## TODO

https://medium.com/hootsuite-engineering/building-docker-images-inside-kubernetes-42c6af855f25

## MicroScanner Wrapper

```
DOCKER_HOST="tcp://localhost:2375" \
  USE_LOCAL=1 \
  MICROSCANNER_TOKEN=${MICROSCANNER_TOKEN}" \
  scan.sh core.harbor.domain/library/mongo:3.6.13-xenial
```
