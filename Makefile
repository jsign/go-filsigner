GO_FLAGS=CGO_ENABLED=0

check-cgo-free:
	$(GO_FLAGS) go build ./...
.PHONY: check-cgo-free

test:
	$(GO_FLAGS) go test ./... 
	go test ./... -race # -race requires CGO
.PHONY: test

