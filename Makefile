.PHONY: all
all: lint test

.PHONY: test
test: go-test

.PHONY: crossbuild-check
crossbuild-check: build-linux build-windows

.PHONY: build-linux
build-linux:
	GOOS=linux go build ./...

.PHONY: build-windows
build-windows:
	GOOS=windows go build ./...

.PHONY: lint
lint: go-mod go-vet go-fmt go-imports

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
