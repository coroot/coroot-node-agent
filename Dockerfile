FROM golang:1.23-bullseye AS builder
RUN apt update && apt install -y libsystemd-dev
WORKDIR /tmp/src
COPY go.mod .
COPY go.sum .
RUN go mod download
COPY . .
ARG VERSION=unknown
RUN CGO_ENABLED=1 go build -mod=readonly -ldflags "-X 'github.com/coroot/coroot-node-agent/flags.Version=${VERSION}'" -o coroot-node-agent .

FROM registry.access.redhat.com/ubi9/ubi

ARG VERSION=unknown
LABEL name="coroot-node-agent" \
      vendor="Coroot, Inc." \
      version=${VERSION} \
      summary="Coroot Node Agent."

COPY LICENSE /licenses/LICENSE

COPY --from=builder /tmp/src/coroot-node-agent /usr/bin/coroot-node-agent
ENTRYPOINT ["coroot-node-agent"]
