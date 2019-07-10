FROM alpine

RUN apk add --no-cache ca-certificates && update-ca-certificates

ADD data /app/data
ADD bin/microscanner-adapter /app/microscanner-adapter

# Add Microscanner
ADD https://get.aquasec.com/microscanner /app
RUN chmod +x /app/microscanner

ENTRYPOINT ["/app/microscanner-adapter"]
