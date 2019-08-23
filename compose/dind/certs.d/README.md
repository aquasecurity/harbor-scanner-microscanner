# `/etc/docker/certs.d`

This directory allows you to configure custom [registry certificates][registry-certificates].
It's mounted at `/etc/docker/certs.d` in the `dind` container (see `docker-compose.yaml`):

```
/etc/docker/certs.d/            <-- Certificates directory
    |-- localhost:5000          <-- Hostname:port
    |  |-- client.cert          <-- Client certificate
    |  |-- client.key           <-- Client key
    |  `-- ca.crt               <-- Certificate authority that signed the registry certificate
    `-- core.harbor.domain      <-- Harbor registry hostname:port
        `-- ca.crt              <-- Certificate authority that signed the Harbor registry certificate
```

TODO Describe how to configure insecure registries (nice to have for development).

[registry-certificates]: https://docs.docker.com/engine/security/certificates/
