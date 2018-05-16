GO?=go

.PHONY: clean providers brokerd broker system clean deps

all: providers broker system

providers:
	@(cd providers && $(MAKE))

broker:
	@(cd broker && $(MAKE))

system:
	@(cd system && $(MAKE))

clean:
	@(cd providers && $(MAKE) $@)
	@(cd broker && $(MAKE) $@)


# DEPENDENCIES HANDLING
STRINGER := golang.org/x/tools/cmd/stringer
RICE := github.com/GeertJohan/go.rice

deps: DEPS := $(STRINGER) $(RICE)

deps: ; @$(GO) get $(DEPS)

