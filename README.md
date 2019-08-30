[![GitHub release][release-img]][release]
[![Build Status][ci-img]][ci]
[![Coverage Status][cov-img]][cov]
[![Go Report Card][report-card-img]][report-card]
[![License][license-img]][license]

# harbor-scanner-microscanner

This project is a POC of an out-of-tree implementation of the Harbor Scanner Adapter API for [MicroScanner][microscanner-url].
See [Pluggable Image Vulnerability Scanning Proposal][image-vulnerability-scanning-proposal] for more details.

## TOC

- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Run with Docker](#run-with-docker)
- [Deploy to minikube](#deploy-to-minikube)
- [Test Images](#test-images)
- [Troubleshooting](#troubleshooting)
- [References](#references)

## Quick Start

1. Generate a unique identifier for a scan request:
   ```
   SCAN_REQUEST_ID=$(uuidgen | tr "[:upper:]" "[:lower:]")
   ```
2. Submit the scan request:
   ```
   curl http://localhost:8080/api/v1/scan \
   -H 'Content-Type: application/json; charset=utf-8' \
   -d @- << EOF
   {
     "id": "${SCAN_REQUEST_ID}",
     "registry_url": "docker.io",
     "registry_authorization": "${REGISTRY_AUTHORIZATION}",
     "artifact_repository": "library/mongo",
     "artifact_digest": "sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e"
   }
   EOF
   ```
3. Get a vulnerabilities report in Harbor Web Console's format:
   ```
   curl -H 'Accept: application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0' \
     http://localhost:8080/api/v1/scan/${SCAN_REQUEST_ID}/report
   ```
4. Get a vulnerabilities report in MicroScanner's format:
   ```
   curl -H 'Accept: application/vnd.scanner.adapter.vuln.report.raw' \
     http://localhost:8080/api/v1/scan/${SCAN_REQUEST_ID}/report
   ```

## Configuration

| Name                            | Default Value            | Description |
|---------------------------------|--------------------------|-------------|
| `SCANNER_API_ADDR`              | `:8080`                  | Binding address for the API HTTP server. |
| `SCANNER_DOCKER_HOST`           | `tcp://localhost:2375`   | Docker Engine URL |
| `SCANNER_MICROSCANNER_TOKEN`    |                          | A token issued by Aqua Security for using the MicroScanner. |
| `SCANNER_MICROSCANNER_OPTIONS`  | `--continue-on-failure --full-output` | Additional options passed as CLI arguments to the MicroScanner. |
| `SCANNER_STORE_DRIVER`          | `redis`                  | A driver used to store scan requests and reports. |
| `SCANNER_STORE_REDIS_URL`       | `redis://localhost:6379`            | Redis server URL in Redis URI scheme for a redis store. |
| `SCANNER_STORE_REDIS_NAMESPACE` | `harbor.scanner.microscanner:store` | A namespace for keys in a redis store. |
| `SCANNER_STORE_REDIS_POOL_MAX_ACTIVE` | 5 | The max number of connections allocated by the pool for a redis store. |
| `SCANNER_STORE_REDIS_POOL_MAX_IDLE`   | 5 | The max number of idle connections in the pool for a redis store. |
| `SCANNER_JOB_QUEUE_REDIS_URL`         | `redis://localhost:6379`                | Redis server URL in Redis URI scheme for a jobs queue. |
| `SCANNER_JOB_QUEUE_REDIS_NAMESPACE`   | `harbor.scanner.microscanner:job-queue` | A namespace for keys in  a jobs queue. |
| `SCANNER_JOB_QUEUE_REDIS_POOL_MAX_ACTIVE` | 5 | The max number of connections allocated by the pool for a jobs queue. |
| `SCANNER_JOB_QUEUE_REDIS_POOL_MAX_IDLE`   | 5 | The max number of idle connections in the pool for a jobs queue. |
| `SCANNER_JOB_QUEUE_WORKER_CONCURRENCY`    | 1 | The number of workers to spin-up for a jobs queue. |

## Run with Docker

```
export SCANNER_MICROSCANNER_TOKEN="***"
```

```
make compose-up
make compose-down
```

## Deploy to minikube

1. Configure Docker client with Docker Engine in minikube:
   ```
   eval $(minikube docker-env -p harbor)
   ```
2. Build Docker container:
   ```
   make container
   ```
3. Create the `harbor-scanner-microscanner` secret with MicroScanner token:
   ```
   kubectl create secret generic harbor-scanner-microscanner \
     --from-literal="microscanner-token=${SCANNER_MICROSCANNER_TOKEN}"
   ```
4. Create the `harbor-scanner-microscanner` config map with Harbor registry certificate:
   ```
   kubectl create configmap harbor-scanner-microscanner \
     --from-file="harbor-registry-cert=${HARBOR_REGISTRY_CERT}"
   ```
5. Create `harbor-scanner-microscanner` deployment and service:
   ```
   kubectl apply -f kube/harbor-scanner-microscanner.yaml
   ```
6. If everything is fine you should be able to get scanner's metadata:
   ```
   kubectl port-forward service/harbor-scanner-microscanner 8080:8080 &> /dev/null &
   curl -v http://localhost:8080/api/v1/metadata | jq
   ```

## Test Images

| Registry  | Repository           | Tag        | Digest                                                                  |
|-----------|----------------------|------------|-------------------------------------------------------------------------|
| docker.io | library/mongo        | 3.4-xenial | sha256:917f5b7f4bef1b35ee90f03033f33a81002511c1e0767fd44276d4bd9cd2fa8e |
| docker.io | library/nginx        | 1.17.2     | sha256:eb3320e2f9ca409b7c0aa71aea3cf7ce7d018f03a372564dbdb023646958770b |
| docker.io | library/debian       | 9.9-slim   | sha256:0c04edb9ae10feb7ac03a659dd41e16c79e04fdb2b10cf93c3cbcef1fd6cc1d5 |
| docker.io | library/debian       | bullseye   | sha256:fe4612b98b35c8ae4719a6a8d5e98432b4b297767a8aebfd858c48f98ecebb7b |
| quay.io   | coreos/clair         | v2.0.8     | sha256:303c7b22e1778acb7c624cca01bad8d3bc5a1b25922d59d28908f223639d9722 |
| docker.io | library/oracle/nosql | 4.3.11     | sha256:df0dc81e03cb1ea29dd68124608fbea35a16dd954ae2e0a6acdeecd739721e8e |
| https://core.harbor.domain/v2         | scanners/nginx | latest | sha256:099019968725f0fc12c4b69b289a347ae74cc56da0f0ef56e8eb8e0134fc7911 |
| http://harbor-harbor-registry:5000/v2 | scanners/nginx | latest | sha256:099019968725f0fc12c4b69b289a347ae74cc56da0f0ef56e8eb8e0134fc7911 |

## Troubleshooting

### `Error: Get https://core.harbor.domain/v2/: x590: certificate signed by unknown authority`

If you are using a custom or self-signed Harbor registry certificate, make sure that it is added to the
`/etc/docker.certs.d` directory in the `dind` container. For example, the certificate for the registry accessible
at https://core.harbor.domain/v2 should be stored under `/etc/docker/certs.d/core.harbor.domain/ca.crt`.

### `Error: pull access denied for core.harbor.domain/scanners/nginx, repository does not exist or may require 'docker login'`

TODO Describe the usage of `~/.docker/config.json` and JWT Access Token expiry.

```
export ACCESS_TOKEN="JWTTOKENGOESHERE"
mkdir -p ~/.docker
cat <<EOF > ~/.docker/config.json
{
  "auths": {
    "core.harbor.domain": {
      "registrytoken": "${ACCESS_TOKEN}"
    }
  },
  "HttpHeaders": {
    "User-Agent": "Harbor Scanner Microscanner"
  }
}
EOF
```

### `Error: Get https://harbor-harbor-registry:5000/v2/: http: server gave HTTP response to HTTPS client`

Most likely you are using an insecure registry which should be explicitly declared in the `/etc/docker/daemon.json`
config file or as the `--insecure-registry` flag.

## References

1. https://medium.com/hootsuite-engineering/building-docker-images-inside-kubernetes-42c6af855f25
2. https://redis.io/topics/data-types-intro
3. https://itnext.io/storing-go-structs-in-redis-using-rejson-dab7f8fc0053

[microscanner-url]: https://github.com/aquasecurity/microscanner
[image-vulnerability-scanning-proposal]: https://github.com/goharbor/community/pull/98

[release-img]: https://img.shields.io/github/release/aquasecurity/harbor-scanner-microscanner.svg
[release]: https://github.com/aquasecurity/harbor-scanner-microscanner/releases
[ci-img]: https://travis-ci.org/aquasecurity/harbor-scanner-microscanner.svg?branch=master
[ci]: https://travis-ci.org/aquasecurity/harbor-scanner-microscanner
[cov-img]: https://codecov.io/github/aquasecurity/harbor-scanner-microscanner/branch/master/graph/badge.svg
[cov]: https://codecov.io/github/aquasecurity/harbor-scanner-microscanner
[report-card-img]: https://goreportcard.com/badge/github.com/aquasecurity/harbor-scanner-microscanner
[report-card]: https://goreportcard.com/report/github.com/aquasecurity/harbor-scanner-microscanner
[license-img]: https://img.shields.io/github/license/aquasecurity/harbor-scanner-microscanner.svg
[license]: https://github.com/aquasecurity/harbor-scanner-microscanner/blob/master/LICENSE
