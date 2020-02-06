include ../../../../../common.mk

.PHONY:  clean generate vet

all: generate

vet:
	@$(GO) vet ./...

generate:
	@(cd flavors ; $(MAKE) $(@))

clean:
	@(cd flavors ; $(MAKE) $(@))
