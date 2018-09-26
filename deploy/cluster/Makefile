GO?=go

.PHONY: api flavors tests clean mrproper

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

mrproper: clean
	@(cd tests && rm -f debug)
	@($(RM) flavors/dcos/rice-box.go)
	@($(RM) flavors/boh/rice-box.go)
