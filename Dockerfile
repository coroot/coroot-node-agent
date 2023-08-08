FROM golang:1.19-bullseye AS builder
RUN apt update && apt install -y libsystemd-dev
COPY go.mod /tmp/src/
COPY go.sum /tmp/src/
WORKDIR /tmp/src/
RUN go mod download
COPY . /tmp/src/
RUN CGO_ENABLED=1 go test ./...
ARG VERSION=unknown
RUN CGO_ENABLED=1 go install -mod=readonly -ldflags "-X main.version=$VERSION" /tmp/src

FROM debian:bullseye
RUN apt update && apt install -y ca-certificates && apt clean
COPY --from=builder /go/bin/coroot-node-agent /usr/bin/coroot-node-agent
ENTRYPOINT ["coroot-node-agent"]
