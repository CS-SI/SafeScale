GO?=go

.PHONY: clean providers brokerd broker system perform clean deps

all: providers broker system perform

providers:
	@(cd providers && $(MAKE))

broker:
	@(cd broker && $(MAKE))

system:
	@(cd system && $(MAKE))

perform:
	@(cd perform && $(MAKE))

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

deps: DEPS := $(STRINGER) $(RICE) $(URFAVE) $(VIPER)

deps: ; @$(GO) get $(DEPS)

