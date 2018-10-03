GO?=go

.PHONY: api flavors tests clean

DIRECTORIES := $(sort $(dir $(wildcard */)))

all: api flavors tests

vet:
	@$(GO) vet ./...

api:
	@(cd api && $(MAKE))

flavors:
	@(cd flavors && $(MAKE))

tests: api flavors
	@(cd tests && $(MAKE))

clean:
	@(cd api && $(MAKE) $@)
	@(cd flavors && $(MAKE) $@)
	@(cd tests && $(MAKE) $@)
	@(cd enums && $(MAKE) $@)
	@($(RM) ./mocks/*.go || true)
	@(for d in $(DIRECTORIES); do (cd $$d; $(RM) *_string.go || true); done)

