FROM alpine

ADD data /app/data
ADD bin/microscanner-proxy /app/microscanner-proxy

ENTRYPOINT ["./app/microscanner-proxy"]
