GO?=go

.PHONY: dcos boh ohpc tests clean

all: dcos boh ohpc

vet:
	@$(GO) vet ./...

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

