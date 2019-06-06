GO?=go

.PHONY:	clean test

all: generate

generate:
	@$(GO) generate -tags libvirt

vet:
	@$(GO) vet ./...

test:
	@$(GO) test
