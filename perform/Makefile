all: cluster command

.PHONY: cluster command clean

cluster:
	@(cd cluster && $(MAKE))

command:
	@(cd command && $(MAKE))

clean:
	@(cd cluster && $(MAKE) $@)
	@(cd command && $(MAKE) $@)

