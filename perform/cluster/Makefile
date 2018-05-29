all: api components dcos tests

.PHONY: api components dcos tests clean mrproper

api:
	@(cd api && $(MAKE))

dcos:
	@(cd dcos && $(MAKE))

components:
	@(cd components && $(MAKE))

tests: api dcos
	@(cd tests && $(MAKE))

clean:
	@(cd api && $(MAKE) $@)
	@(cd dcos && $(MAKE) $@)
	@(cd tests && $(MAKE) $@)

mrproper: clean
	@(cd tests && rm -f debug)
	@(rm -f dcos/rice-box.go)

