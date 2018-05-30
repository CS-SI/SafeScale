.PHONY: api components dcos tests clean mrproper

all: api components dcos tests

api:
	@(cd api && $(MAKE))

components:
	@(cd components && $(MAKE))

dcos:
	@(cd dcos && $(MAKE))

tests: api dcos
	@(cd tests && $(MAKE))

clean:
	@(cd api && $(MAKE) $@)
	@(cd dcos && $(MAKE) $@)
	@(cd tests && $(MAKE) $@)
	@(cd components && $(MAKE) $@)

mrproper: clean
	@(cd tests && rm -f debug)
	@($(RM) dcos/rice-box.go)

