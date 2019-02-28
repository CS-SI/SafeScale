GO?=go

.PHONY: generate flavors tests clean

DIRECTORIES := $(sort $(dir $(wildcard */)))

all: api flavors tests

vet:
	@$(GO) vet ./...

generate:
	@$(GO) generate ./...

flavors: generate
	@(cd flavors && $(MAKE))

tests: generate flavors
	@(cd tests && $(MAKE))

clean:
	@(cd api && $(MAKE) $@)
	@(cd flavors && $(MAKE) $@)
	@(cd tests && $(MAKE) $@)
	@(cd enums && $(MAKE) $@)
	@($(RM) ./mocks/*.go || true)
