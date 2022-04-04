include ../../../../common.mk

.PHONY:	clean vet

DIRECTORIES := $(sort $(dir $(wildcard */)))

generate: clean
	@(mkdir -p mocks) || true
	@$(GO) generate ./...

vet:
	@$(GO) vet ./...

clean:
	@:
