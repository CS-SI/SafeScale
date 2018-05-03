all: providers system broker cluster

.PHONY: clean providers broker cluster clean

providers:
	@(cd providers && $(MAKE))

broker:
	@(cd broker && $(MAKE))

cluster:
	@(cd cluster && $(MAKE))

clean:
	@(cd providers && $(MAKE) $@)
	@(cd broker && $(MAKE) $@)
	@(cd cluster && $(MAKE) $@)
	@(cd system && $(MAKE) $@)

