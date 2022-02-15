include ../../../../common.mk

.PHONY:	clean vet

DIRECTORIES := $(sort $(dir $(wildcard */)))

generate: clean
	@:

vet:
	@$(GO) vet ./...

clean:
	@:
