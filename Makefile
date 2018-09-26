.DEFAULT_GOAL := help

.PHONY: default
default: help ;

ifndef VERBOSE
MAKEFLAGS += --no-print-directory
endif

GO?=go
GOBIN?=~/go/bin
CP?=cp

EXECS=broker/cli/broker/broker broker/cli/brokerd/brokerd deploy/cli/deploy perform/perform

PKG_LIST := $(shell $(GO) list ./... | grep -v /vendor/)
TESTABLE_PKG_LIST := $(shell $(GO) list ./... | grep -v /vendor/ | grep -v /deploy | grep -v /providers/aws )

COM_COLOR   = \033[0;34m
OBJ_COLOR   = \033[0;36m
OK_COLOR    = \033[0;32m
ERROR_COLOR = \033[0;31m
WARN_COLOR  = \033[0;33m
NO_COLOR    = \033[m

OK_STRING    = "[OK]"
ERROR_STRING = "[ERROR]"
WARN_STRING  = "[WARNING]"

all: ground getdevdeps ensure generate providers broker system deploy perform utils

ground:
	@command -v git >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)I require git but it's not installed.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }
	@command -v $(GO) >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)I require go but it's not installed.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }
	@command -v protoc >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)I require protoc but it's not installed.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }

getdevdeps:
	@printf "%b" "$(OK_COLOR)Testing prerequisites, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@which dep rice stringer protoc-gen-go cover > /dev/null; if [ $$? -ne 0 ]; then \
    	  $(GO) get -u $(STRINGER) $(RICE) $(PROTOBUF) $(COVER) $(DEP); \
    fi

ensure:
	@printf "%b" "$(OK_COLOR)Checking versions, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@($(GOBIN)/dep ensure)

utils:
	@printf "%b" "$(OK_COLOR)Building utils, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd utils && $(MAKE) all)

providers:
	@printf "%b" "$(OK_COLOR)Building providers, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd providers && $(MAKE) all)

system:
	@printf "%b" "$(OK_COLOR)Building system, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd system && $(MAKE) all)

broker: utils system providers
	@printf "%b" "$(OK_COLOR)Building broker, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd broker && $(MAKE) all)

deploy: utils system providers broker
	@printf "%b" "$(OK_COLOR)Building deploy, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd deploy && $(MAKE) all)

perform: utils system providers broker
	@printf "%b" "$(OK_COLOR)Building perform, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd perform && $(MAKE) all)

clean:
	@printf "%b" "$(OK_COLOR)Cleaning..., $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd providers && $(MAKE) $@)
	@(cd system && $(MAKE) $@)
	@(cd broker && $(MAKE) $@)
	@(cd deploy && $(MAKE) $@)
	@(cd perform && $(MAKE) $@)

broker/client/broker: broker
	@printf "%b" "$(OK_COLOR)Building broker, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";

broker/daemon/brokerd: broker
	@printf "%b" "$(OK_COLOR)Building broker daemon, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";

deploy/cli/deploy: deploy
	@printf "%b" "$(OK_COLOR)Building deploy, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";

perform/perform: perform
	@printf "%b" "$(OK_COLOR)Building perform, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";

install: $(EXECS)
	@($(CP) -f $^ $(GOBIN))

# DEPENDENCIES MANAGEMENT
#Generate enum tring
STRINGER := golang.org/x/tools/cmd/stringer
#Embed shell file into code go
RICE := github.com/GeertJohan/go.rice github.com/GeertJohan/go.rice/rice

PROTOC := github.com/golang/protobuf
PROTOBUF := github.com/golang/protobuf/protoc-gen-go

COVER := golang.org/x/tools/cmd/cover
DEP := github.com/golang/dep/cmd/dep

DEVDEPSLIST := $(STRINGER) $(RICE) $(PROTOBUF) $(DEP) $(COVER)

docs:
	@printf "%b" "$(OK_COLOR)Running godocs in background, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(godoc -http=:6060 &)

devdeps:
	@printf "%b" "$(OK_COLOR)Getting dev dependencies, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@($(GO) get -u $(DEVDEPSLIST))

depclean:
	@printf "%b" "$(OK_COLOR)Cleaning vendor and redownloading deps, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@rm ./Gopkg.toml
	@rm -rf ./vendor
	@(dep ensure)

generate: # Run unit tests
	@printf "%b" "$(OK_COLOR)Running code generation, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@($(GO) generate ./...) | tee generation_results.log

test: # Run unit tests
	@printf "%b" "$(OK_COLOR)Running unit tests, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(GO) test -short ${TESTABLE_PKG_LIST} | tee test_results.log

vet:
	@printf "%b" "$(OK_COLOR)Running vet checks, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(GO) vet ${TESTABLE_PKG_LIST} | tee vet_results.log

help:
	@echo ''
	@echo 'BUILD TARGETS:'
	@echo '  help         - Prints this help message'
	@echo '  docs         - Runs godoc in background at port 6060.'
	@echo '                 Go to (http://localhost:6060/pkg/github.com/CS-SI/)'
	@echo '  all          - Builds all binaries'
	@echo '  install      - Copies all binaries to $(GOBIN)'
	@echo ''
	@echo 'CLEANING TARGETS:'
	@echo '  clean        - Removes files generated by build'
	@echo '  depclean     - Removes project dependencies first, then downloads a fresh copy'
	@echo ''
	@echo 'TESTING TARGETS:'
	@echo '  vet          - Runs all checks'
	@echo '  test         - Runs all tests'
	@echo '  coverage     - Collects coverage info from unit tests'
	@echo ''
	@echo 'DEV TARGETS:'
	@echo '  devdeps      - Downloads tool dependencies'
	@echo '  depclean     - Rebuilds vendor dependencies'
	@echo ''
	@echo
