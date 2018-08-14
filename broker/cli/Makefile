GO?=go

.PHONY:	broker brokerd clean vet

all:	broker brokerd

vet:
	@(cd broker && $(MAKE) $@)
	@(cd brokerd && $(MAKE) $@)

broker:
	@(cd broker && $(MAKE))

brokerd:
	@(cd brokerd && $(MAKE))

clean:
	@(cd broker && $(MAKE) $@)
	@(cd brokerd && $(MAKE) $@)
