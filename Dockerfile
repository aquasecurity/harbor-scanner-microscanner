FROM alpine:3.10.1

RUN apk add --no-cache docker bash ca-certificates && update-ca-certificates

ADD bin/scanner-microscanner /app/scanner-microscanner

# Add Microscanner executable
ADD https://get.aquasec.com/microscanner /usr/local/bin
RUN chmod +x /usr/local/bin/microscanner

# Add Microscanner Wrapper script
ADD microscanner/wrapper.sh /usr/local/bin/microscanner-wrapper.sh

ENTRYPOINT ["/app/scanner-microscanner"]
