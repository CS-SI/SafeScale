GO?=go

.PHONY:	clean generate vet

DIRECTORIES := $(sort $(dir $(wildcard */)))

all:	generate

vet:
	@$(GO) vet ./...

generate:
	@$(GO) generate ./...

clean: ;