GO?=go

.PHONY:	clean test

all: generate

generate:
	@$(GO) generate

vet:
	@$(GO) vet $(BUILD_TAGS) ./...

test:
	@$(GO) test
