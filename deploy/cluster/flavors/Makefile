GO?=go

.PHONY: dcos boh ohpc tests clean mrproper

all: dcos boh ohpc

vet:

dcos:
	@(cd dcos && $(MAKE))

boh:
	@(cd boh && $(MAKE))

ohpc:
	@(cd ohpc && $(MAKE))

tests: dcos boh ohpc
	@(cd tests && $(MAKE))

clean:
	@(cd dcos && $(MAKE) $@)
	@(cd boh && $(MAKE) $@)
	@(cd ohpc && $(MAKE) $@)
	#@(cd tests && $(MAKE) $@)

mrproper: clean
	#@(cd tests && rm -f debug)
