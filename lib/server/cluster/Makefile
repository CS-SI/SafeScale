GO?=go

.PHONY: clean flavors generate vet

DIRECTORIES := $(sort $(dir $(wildcard */)))

all: flavors

vet:
	@$(GO) vet ./...

flavors: generate
	@(cd flavors && $(MAKE) all)

generate: clean
	@(mkdir -p mocks || true)
	@(cd enums && $(MAKE) $(@))
	@(cd flavors && $(MAKE) $(@))

clean:
	@(cd flavors && $(MAKE) $@)
	@(cd enums && $(MAKE) $@)
	@($(RM) ./mocks/*.go || true)
	@(rmdir mocks 2>/dev/null || true)
