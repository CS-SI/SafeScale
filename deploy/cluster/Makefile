GO?=go

.PHONY: api components flavors tests clean mrproper

all: api components flavors tests

vet:
	@$(GO) vet

api:
	@(cd api && $(MAKE))

components:
	@(cd components && $(MAKE))

flavors:
	@(cd flavors && $(MAKE))

tests: api flavors
	@(cd tests && $(MAKE))

clean:
	@(cd api && $(MAKE) $@)
	@(cd flavors && $(MAKE) $@)
	@(cd tests && $(MAKE) $@)
	@(cd components && $(MAKE) $@)

mrproper: clean
	@(cd tests && rm -f debug)
	@($(RM) flavors/dcos/rice-box.go)
	@($(RM) flavors/boh/rice-box.go)
