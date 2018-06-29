GO?=go

.PHONY: clean providers brokerd broker system perform utils clean deps

all: providers system broker perform utils

providers:
	@(cd providers && $(MAKE))

broker: system
	@(cd broker && $(MAKE))

system:
	@(cd system && $(MAKE))

perform: utils
	@(cd perform && $(MAKE))

utils: broker
	@(cd utils && $(MAKE))

clean:
	@(cd providers && $(MAKE) $@)
	@(cd system && $(MAKE) $@)
	@(cd broker && $(MAKE) $@)
	@(cd perform && $(MAKE) $@)


# DEPENDENCIES MANAGEMENT
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

CRYPTO_SSH := golang.org/x/crypto/ssh

# GRPC LIBS
CONTEXT := golang.org/x/net/context
GRPC := google.golang.org/grpc
PROTOBUF := github.com/golang/protobuf/protoc-gen-go
GRPC_LIBS := $(GRPC) $(PROTOBUF) $(CONTEXT)

## Providers SDK
# OpenStack SDK for GO
GOPHERCLOUD := github.com/gophercloud/gophercloud
# AWS SDK for GO
AWS := github.com/aws/aws-sdk-go
# Providers SDK
PROVIDERS_SDK := $(GOPHERCLOUD) $(AWS)

DEPS := $(STRINGER) $(RICE) $(URFAVE) $(VIPER) $(PENGUS_CHECK) $(UUID) $(SPEW) $(DSP) $(TESTIFY) $(CRYPTO_SSH) $(GRPC_LIBS) $(PROVIDERS_SDK)

deps: ; $(GO) get -u $(DEPS)
