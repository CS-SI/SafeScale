GO?=go

.PHONY: vet clean

DIRECTORIES := $(sort $(dir $(wildcard */)))

vet:
	@($(GO) vet ./...)
