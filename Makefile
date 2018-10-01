.DEFAULT_GOAL := help

.PHONY: default
default: help ;

ifndef VERBOSE
MAKEFLAGS += --no-print-directory
endif

VERSION := 0.1.0
BUILD := `git rev-parse HEAD`

GO?=go
GOBIN?=$(GOPATH)/bin
CP?=cp

# Handling multiple gopath: use ~/go by default
ifeq ($(findstring :,$(GOBIN)),:)
    GOBIN=~/go/bin
endif

# Binaries generated
EXECS=broker/cli/broker/broker broker/cli/brokerd/brokerd deploy/cli/deploy perform/perform

# List of packages
PKG_LIST := $(shell $(GO) list ./... | grep -v /vendor/)
# List of packages to test (nor deploy neither providers are ready for prime time :( )
TESTABLE_PKG_LIST := $(shell $(GO) list ./... | grep -v /vendor/ | grep -v /deploy | grep -v /providers/aws )


# DEPENDENCIES MANAGEMENT
STRINGER := golang.org/x/tools/cmd/stringer
RICE := github.com/GeertJohan/go.rice github.com/GeertJohan/go.rice/rice
PROTOC := github.com/golang/protobuf
PROTOBUF := github.com/golang/protobuf/protoc-gen-go

# Build tools
COVER := golang.org/x/tools/cmd/cover
LINTER := golang.org/x/lint/golint
DEP := github.com/golang/dep/cmd/dep

DEVDEPSLIST := $(STRINGER) $(RICE) $(PROTOBUF) $(DEP) $(COVER)


# Life is better with colors
COM_COLOR   = \033[0;34m
OBJ_COLOR   = \033[0;36m
OK_COLOR    = \033[0;32m
GOLD_COLOR  = \033[0;93m
ERROR_COLOR = \033[0;31m
WARN_COLOR  = \033[0;33m
NO_COLOR    = \033[m

OK_STRING    = "[OK]"
INFO_STRING  = "[INFO]"
ERROR_STRING = "[ERROR]"
WARN_STRING  = "[WARNING]"

all: begin ground getdevdeps ensure generate providers broker system deploy perform utils
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Build SUCCESSFUL $(NO_COLOR)\n";

common: begin ground getdevdeps ensure generate

begin:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Build begins...$(NO_COLOR)\n";

ground:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Testing tool prerequisites, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@command -v git >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) git is required but it's not installed.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }
	@command -v $(GO) >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) go is required but it's not installed.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }
	@command -v protoc >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) protoc is required but it's not installed.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }

getdevdeps: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Testing prerequisites, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@which dep rice stringer protoc-gen-go golint cover > /dev/null; if [ $$? -ne 0 ]; then \
    	  $(GO) get -u $(STRINGER) $(RICE) $(PROTOBUF) $(COVER) $(LINTER) $(DEP); \
    fi

ensure:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Checking versions, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@if [ ! -d ./vendor ]; then printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading all dependencies from zero, this is gonna take a while..., $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n"; else printf "%b" "$(OK_COLOR)$(INFO_STRING) Updating vendor dir..., $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n"; fi;
	@(dep ensure)

utils: common
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Building utils, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd utils && $(MAKE) all)

providers: common
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Building providers, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd providers && $(MAKE) all)

system: common
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Building system, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd system && $(MAKE) all)

broker: common utils system providers
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Building service broker, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd broker && $(MAKE) all)

deploy: common utils system providers broker
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Building service deploy, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd deploy && $(MAKE) all)

perform: common utils system providers broker
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Building service perform, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd perform && $(MAKE) all)# List of packages

clean:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Cleaning..., $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd providers && $(MAKE) $@)
	@(cd system && $(MAKE) $@)
	@(cd broker && $(MAKE) $@)
	@(cd deploy && $(MAKE) $@)
	@(cd perform && $(MAKE) $@)

broker/client/broker: broker
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Building service broker (client) , $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";

broker/daemon/brokerd: broker
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Building service broker (daemon) , $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";

deploy/cli/deploy: deploy
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Building service deploy, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";

perform/perform: perform
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Building service perform, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";

install: $(EXECS)
	@($(CP) -f $^ $(GOBIN))

docs:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running godocs in background, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(godoc -http=:6060 &)

devdeps:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Getting dev dependencies, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@($(GO) get -u $(DEVDEPSLIST))

depclean: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Cleaning vendor and redownloading deps, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@if [ -f ./Gopkg.lock ]; then rm ./Gopkg.lock; fi;
	@rm -rf ./vendor
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading all dependencies from zero, this is gonna take a while..., $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(dep ensure)

generate: # Run unit tests
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running code generation, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(GO) generate ./... 2>&1 | tee generation_results.log

test: begin # Run unit tests
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running unit tests, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(GO) test -short ${PKG_LIST} 2>&1 | tee test_results.log
	@if [ -s ./test_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) tests FAILED !$(NO_COLOR)\n";else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. TESTS PASSED ! $(NO_COLOR)\n";fi;

test-light: begin # Run unit tests
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running unit tests (with restrictions), $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(GO) test -short ${TESTABLE_PKG_LIST} 2>&1 | tee test_results.log
	@if [ -s ./test_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) tests (with restrictions) FAILED !$(NO_COLOR)\n";else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. TESTS PASSED ! $(NO_COLOR)\n";fi;

vet-light: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running vet checks (with restrictions), $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(GO) vet ${TESTABLE_PKG_LIST} 2>&1 | tee vet_results.log
	@if [ -s ./vet_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) vet (with restrictions) FAILED !$(NO_COLOR)\n";else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. NO PROBLEMS DETECTED ! $(NO_COLOR)\n";fi;

vet: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running vet checks, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(GO) vet ${PKG_LIST} 2>&1 | tee vet_results.log
	@if [ -s ./vet_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) vet FAILED !$(NO_COLOR)\n";else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. NO PROBLEMS DETECTED ! $(NO_COLOR)\n";fi

lint: begin
	@$(GO) list ./... | grep -v /vendor/ | xargs -L1 golint

coverage: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Collecting coverage data, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@printf "%b" "$(WARN_COLOR)$(WARN_STRING) Not ready, coming soon ;) , $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";

help:
	@echo ''
	@printf "%b" "$(GOLD_COLOR) **************** SAFESCALE BUILD ****************$(NO_COLOR)\n";
	@echo ' If in doubt, try "make all"'
	@echo ''
	@printf "%b" "$(OK_COLOR)BUILD TARGETS:$(NO_COLOR)\n";
	@printf "%b" "  $(GOLD_COLOR)all          - Builds all binaries$(NO_COLOR)\n";
	@echo '  help         - Prints this help message'
	@echo '  docs         - Runs godoc in background at port 6060.'
	@echo '                 Go to (http://localhost:6060/pkg/github.com/CS-SI/)'
	@echo '  install      - Copies all binaries to $(GOBIN)'
	@echo ''
	@printf "%b" "$(OK_COLOR)TESTING TARGETS:$(NO_COLOR)\n";
	@echo '  lint         - Runs linter'
	@echo '  vet          - Runs all checks'
	@echo '  vet-light    - Runs all checks (with restrictions)'
	@echo '  test         - Runs all tests'
	@echo '  test-light   - Runs all tests (with restrictions)'
	@echo '  coverage     - Collects coverage info from unit tests'
	@echo ''
	@printf "%b" "$(OK_COLOR)DEV TARGETS:$(NO_COLOR)\n";
	@echo '  clean        - Removes files generated by build (obsolete, running again "make all" should overwrite everything)'
	@echo '  depclean     - Rebuilds vendor dependencies'
	@echo ''
	@echo
