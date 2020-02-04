GO?=go

.PHONY:	test clean

all: generate

generate: clean
	@$(GO) generate

vet:
	@$(GO) vet ./...

test:
	@$(GO) test

clean: ;