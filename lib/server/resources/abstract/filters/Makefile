GO?=go

.PHONY: vet

DIRECTORIES := $(sort $(dir $(wildcard */)))

vet:
	@($(GO) vet ./...)
