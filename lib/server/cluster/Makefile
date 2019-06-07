GO?=go

.PHONY: clean flavors generate tests vet

DIRECTORIES := $(sort $(dir $(wildcard */)))

all: flavors tests

vet:
	@$(GO) vet ./...

flavors: generate
	@(cd flavors && $(MAKE) all)

generate:
	@(cd enums && $(MAKE) $(@))
	@(cd flavors && $(MAKE) $(@))

tests: flavors
	@(cd tests && $(MAKE) all)

clean:
	@(cd flavors && $(MAKE) $@)
	@(cd tests && $(MAKE) $@)
	@(cd enums && $(MAKE) $@)
	@($(RM) ./mocks/*.go || true)
