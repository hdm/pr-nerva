# IRC Docker build for plugin integration testing
# Builds a mock IRC server simulating common IRC daemons
#
# Build:  docker build -t irc-test .
# Run:    docker run -d --name irc-test -p 6667:6667/tcp irc-test
# Test:   nerva -t 127.0.0.1:6667 --verbose
# Stop:   docker stop irc-test && docker rm irc-test
#
# Environment variables:
#   IRC_PORT          - listening port (default: 6667)
#   IRC_SERVER_NAME   - server hostname (default: irc.mock.local)
#   IRC_NETWORK_NAME  - IRC network name (default: MockNet)
#   IRC_DAEMON        - daemon version string (default: MockIRCd-1.0.0)
#   IRC_USER_COUNT    - reported user count (default: 10)
#   IRC_CHANNEL_COUNT - reported channel count (default: 5)

FROM golang:1.24-alpine AS builder

WORKDIR /build

# Copy mock server source
COPY main.go .

# Build static binary
RUN go build -o irc-mock main.go

FROM alpine:latest

# Copy binary from builder
COPY --from=builder /build/irc-mock /usr/local/bin/irc-mock

# IRC port
EXPOSE 6667/tcp

# Run mock server
CMD ["/usr/local/bin/irc-mock"]
