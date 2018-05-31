GO?=go

.PHONY: clean providers brokerd broker system perform clean deps

all: providers system broker perform

providers:
	@(cd providers && $(MAKE))

broker: providers system
	@(cd broker && $(MAKE))

system:
	@(cd system && $(MAKE))

perform:
	@(cd perform && $(MAKE))

clean:
	@(cd providers && $(MAKE) $@)
	@(cd system && $(MAKE) $@)
	@(cd broker && $(MAKE) $@)
	@(cd perform && $(MAKE) $@)


# DEPENDENCIES HANDLING
#Generate enum tring
STRINGER := golang.org/x/tools/cmd/stringer
#Embed shell file into code go
RICE := github.com/GeertJohan/go.rice github.com/GeertJohan/go.rice/rice
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
PROTOBUF = github.com/golang/protobuf/protoc-gen-go
AWS := github.com/aws/aws-sdk-go
GOPHER := github.com/gophercloud/gophercloud
GOLANG := golang.org/x/crypto/ssh golang.org/x/net/context
GRPC := google.golang.org/grpc

deps: DEPS := $(STRINGER) $(RICE) $(URFAVE) $(VIPER) $(PENGUS_CHECK) $(UUID) $(SPEW) $(DSP) $(TESTIFY) $(PROTOBUF) $(AWS) $(GOPHER) $(GOLANG) $(GRPC)

deps: ; @$(GO) get -u $(DEPS)

