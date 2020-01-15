GO?=go

.PHONY:	clean test

all: generate

generate: clean
	@$(GO) generate

vet:
	@$(GO) vet ./...

test:
	@$(GO) test
