build:
	@go build ./...

test:
	@go test ./...

lint:
	@golangci-lint run

fmt:
	@gofmt -w .

clean:
	@echo "Nothing to clean yet"
