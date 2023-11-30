style-check:
	gofmt -l -d ./.
	goimports -l -d ./.

lint:
	golint ./...
	golangci-lint run --tests="false"

.PHONY: style-check lint
