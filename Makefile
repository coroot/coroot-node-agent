.PHONY: all
all: lint test

.PHONY: test
test: go-test

.PHONY: build
build: lint go-build

.PHONY: lint
lint: go-mod go-vet go-fmt go-imports

.PHONY: go-build
go-build:
	make -C ./ebpftracer ebpf.go
	go build

.PHONY: go-mod
go-mod:
	go mod tidy

.PHONY: go-vet
go-vet:
	go vet ./...

.PHONY: go-fmt
go-fmt:
	gofmt -w .

.PHONY: go-imports
go-imports:
	go install golang.org/x/tools/cmd/goimports@latest
	goimports -w .

.PHONY: go-test
go-test:
	go test ./...

.PHONY: docker
docker:
	docker build . -t registry.cn-beijing.aliyuncs.com/obser/coroot-node-agent:latest
