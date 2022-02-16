include ../../../../common.mk

.PHONY:	clean generate vet

DIRECTORIES := $(sort $(dir $(wildcard */)))

all: generate

generate: clean
	@:

vet:
	@$(GO) vet ./...

clean:
	@:
