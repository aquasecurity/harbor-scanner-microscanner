FROM alpine:3.10.1

RUN apk add --no-cache docker bash ca-certificates && update-ca-certificates

ADD bin/microscanner-adapter /app/microscanner-adapter

# Add Microscanner executable
ADD https://get.aquasec.com/microscanner /usr/local/bin
RUN chmod +x /usr/local/bin/microscanner

# Add Microscanner Wrapper script
ADD microscanner-wrapper/scan.sh /usr/local/bin/

ENTRYPOINT ["/app/microscanner-adapter"]
