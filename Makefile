#all: providers brokerd broker cluster
all: providers cluster

.PHONY: clean providers brokerd broker cluster clean

providers:
	@(cd providers && $(MAKE))

broker:
	@(cd broker && $(MAKE))

cluster:
	@(cd cluster && $(MAKE))

clean:
	@(cd providers && $(MAKE))
	@(cd broker && $(MAKE))
	@(cd cluster && $(MAKE))

