GO?=go

.PHONY: vet

all: generate

generate:
	@$(GO) generate

DIRECTORIES := $(sort $(dir $(wildcard */)))

vet:
	@($(GO) vet ./...)