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
#Generate enum tring
STRINGER := golang.org/x/tools/cmd/stringer
#Embed shell file into code go
RICE := github.com/GeertJohan/go.rice
#CLI parser
URFAVE := github.com/urfave/cli
#Configuration file handler
VIPER := github.com/spf13/viper
#Data validation lib: at least used to validate VM name for flexibleengine
PENGUS_CHECK := github.com/pengux/check

deps: DEPS := $(STRINGER) $(RICE) $(URFAVE) $(VIPER) $(PENGUS_CHECK)

deps: ; @$(GO) get $(DEPS)

