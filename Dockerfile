FROM alpine

RUN apk add --no-cache docker bash ca-certificates && update-ca-certificates

ADD data /app/data
ADD bin/microscanner-adapter /app/microscanner-adapter

# Add Microscanner
ADD https://get.aquasec.com/microscanner /usr/local/bin
RUN chmod +x /usr/local/bin/microscanner

ENTRYPOINT ["/app/microscanner-adapter"]
