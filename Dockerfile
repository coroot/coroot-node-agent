FROM golang:1.21-bullseye AS builder
RUN apt update && apt install -y libsystemd-dev
WORKDIR /tmp/src
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go test ./...
ARG VERSION=unknown
RUN CGO_ENABLED=1 go build -mod=readonly -ldflags "-X main.version=$VERSION" -o coroot-node-agent .

FROM debian:bullseye
RUN apt update && apt install -y ca-certificates && apt clean
COPY --from=builder /tmp/src/coroot-node-agent /usr/bin/coroot-node-agent
ENTRYPOINT ["coroot-node-agent"]
