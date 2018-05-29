GO?=go

.PHONY: clean providers brokerd broker system clean deps

all: providers system broker 

providers:
	@(cd providers && $(MAKE))

broker: providers system
	@(cd broker && $(MAKE))

system:
	@(cd system && $(MAKE))

clean:
	@(cd providers && $(MAKE) $@)
	@(cd system && $(MAKE) $@)
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
UUID := github.com/satori/go.uuid
SPEW := github.com/davecgh/go-spew/spew
DSP := github.com/mjibson/go-dsp/fft
TESTIFY := github.com/stretchr/testify

deps: DEPS := $(STRINGER) $(RICE) $(URFAVE) $(VIPER) $(PENGUS_CHECK) $(UUID) $(SPEW) $(DSP) $(TESTIFY)

deps: ; @$(GO) get $(DEPS)

