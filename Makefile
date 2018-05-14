#all: providers brokerd broker cluster
all: providers broker system

.PHONY: clean providers brokerd broker system clean

providers:
	@(cd providers && $(MAKE))

broker:
	@(cd broker && $(MAKE))

system:
	@(cd system && $(MAKE))

clean:
	@(cd providers && $(MAKE) $@)
	@(cd broker && $(MAKE) $@)

