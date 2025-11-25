PHONY: build, fmt, test, templ, tidy
build:
	go build ./...

run:
	go run cmd/server/main.go

fmt:
	go fmt ./...

test:
	go fmt ./...
	gotestsum --debug -f testname -- -timeout 8s -count=1 ./...

templ:
	templ generate

tidy:
	go mod tidy
