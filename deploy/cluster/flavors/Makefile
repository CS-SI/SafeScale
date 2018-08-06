GO?=go

.PHONY: dcos boh tests clean mrproper

all: dcos boh

vet:

dcos:
	@(cd dcos && $(MAKE))

boh:
	@(cd boh && $(MAKE))

tests: dcos boh
	@(cd tests && $(MAKE))

clean:
	@(cd dcos && $(MAKE) $@)
	@(cd boh && $(MAKE) $@)
	#@(cd tests && $(MAKE) $@)

mrproper: clean
	#@(cd tests && rm -f debug)
