ndef = $(if $(value $(1)),,$(error $(1) not set))

.DEFAULT_GOAL := help

.PHONY: default
default: help ;

#ROOTDIR:=$(shell ROOTDIR='$(ROOTDIR)' bash -c "dirname $(realpath $(lastword $(MAKEFILE_LIST)))")
#export ROOTDIR

include ./common.mk

# Binaries generated
EXECS=cli/safescale/safescale cli/safescale/safescale-cover cli/safescaled/safescaled cli/safescaled/safescaled-cover cli/perform/perform cli/perform/perform-cover cli/scanner/scanner

# List of packages
PKG_LIST := $(shell $(GO) list ./... | grep -v lib/security/ | grep -v /vendor/)
# List of packages to test
TESTABLE_PKG_LIST := $(shell $(GO) list ./... | grep -v /vendor/ | grep -v lib/security/ | grep -v providers/aws | grep -v stacks/aws | grep -v sandbox)


# DEPENDENCIES MANAGEMENT
STRINGER := golang.org/x/tools/cmd/stringer
RICE := github.com/GeertJohan/go.rice github.com/GeertJohan/go.rice/rice
PROTOC := github.com/golang/protobuf
PROTOBUF := github.com/golang/protobuf/protoc-gen-go

# Build tools
CONVEY := github.com/smartystreets/goconvey
MOCKGEN := github.com/golang/mock/gomock github.com/golang/mock/mockgen
COVER := golang.org/x/tools/cmd/cover
LINTER := golang.org/x/lint/golint
DEP := github.com/golang/dep/cmd/dep
ERRCHECK := github.com/kisielk/errcheck
XUNIT := github.com/tebeka/go2xunit
REPORTER := github.com/360EntSecGroup-Skylar/goreporter
COVERTOOL := github.com/dlespiau/covertool
GOVENDOR := github.com/kardianos/govendor

DEVDEPSLIST := $(STRINGER) $(RICE) $(PROTOBUF) $(DEP) $(MOCKGEN) $(COVER) $(LINTER) $(XUNIT) $(ERRCHECK) $(REPORTER) $(COVERTOOL) $(CONVEY) $(GOVENDOR)

BUILD_TAGS = ""
export BUILD_TAGS

all: begin ground getdevdeps ensure generate lib cli err vet-light
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Build SUCCESSFUL $(NO_COLOR)\n";

common: begin ground getdevdeps ensure generate

begin:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Build begins...$(NO_COLOR)\n";

libvirt:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Libvirt driver enabled$(NO_COLOR)\n";
	@systemctl status libvirtd.service >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) libvirt is required but it's not installed.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }
	@lsmod | grep kvm >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) kvm is required but it's not installed.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }
	@grep -E '^flags.*(vmx|svm)' /proc/cpuinfo >/dev/null 2>&1 && \
	if [ $$? -eq 0 ]; then \
		printf "%b" "$(OK_COLOR)$(OK_STRING) Hardware acceleration is available!\n"; \
	else \
		printf "%b" "$(WARN_COLOR)$(WARN_STRING) Hardware acceleration is NOT available!\n"; \
	fi
	$(eval BUILD_TAGS = "--tags=libvirt")

with_git:
	@command -v git >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) git is required but it's not installed.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }

ground:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Testing tool prerequisites, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@command -v git >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) git is required but it's not installed.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }
	@command -v $(GO) >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) go is required but it's not installed.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }
	@command -v protoc >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) protoc is required but it's not installed.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }

getdevdeps: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Testing prerequisites, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@which dep rice stringer protoc-gen-go golint mockgen go2xunit cover covertool convey errcheck goreporter govendor > /dev/null; if [ $$? -ne 0 ]; then \
    	  $(GO) get -u $(STRINGER) $(RICE) $(PROTOBUF) $(COVER) $(LINTER) $(MOCKGEN) $(XUNIT) $(ERRCHECK) $(REPORTER) $(COVERTOOL) $(CONVEY) $(DEP) $(GOVENDOR); \
    fi

ensure:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Checking versions, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@if [ ! -d ./vendor ]; then printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading all dependencies from zero, this is gonna take a while..., $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n"; else printf "%b" "$(OK_COLOR)$(INFO_STRING) Updating vendor dir..., $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n"; fi;
	@(dep ensure)
	@($(GO) install ./vendor/github.com/golang/protobuf/protoc-gen-go)
	@(dep ensure -update "github.com/gophercloud/gophercloud")
	@(dep ensure -update "github.com/graymeta/stow")
	@$(GO) version | grep 1.10 > /dev/null || dep ensure -update "golang.org/x/tools"
	@$(GO) version | grep 1.10 > /dev/null && rm -rf `which stringer` && rm -rf ./vendor/golang.org/x/tools/cmd && govendor fetch golang.org/x/tools/cmd/stringer@release-branch.go1.10 && cd vendor/golang.org/x/tools/cmd/stringer && $(GO) build && mv ./stringer $(GOPATH)/bin || true
	@$(GO) version | grep 1.10 > /dev/null && rm -rf `which errcheck` && rm -rf ./vendor/github.com/kisielk && govendor fetch github.com/kisielk/errcheck@v1.0.1 && cd vendor/github.com/kisielk/errcheck && $(GO) build && mv ./errcheck $(GOPATH)/bin || true

sdk:
	@(cd lib && $(MAKE) $(@))

lib: common
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Building SafeScale libraries, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd lib && $(MAKE) all)

cli: common lib
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Building SafeScale binaries, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd cli && $(MAKE) all)

clean:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Cleaning..., $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd cli && $(MAKE) $(@))
	@(cd lib && $(MAKE) $(@))

install:
	@($(CP) -f $(EXECS) $(GOBIN) || true)

installci:
	@(mkdir -p $(CIBIN) || true)
	@($(CP) -f $(EXECS) $(CIBIN) || true)

godocs:
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
	@($(GO) install ./vendor/github.com/golang/protobuf/protoc-gen-go)
	@(dep ensure -update "github.com/gophercloud/gophercloud")
	@(dep ensure -update "github.com/graymeta/stow")

generate: begin # Run generation
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running code generation, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@cd lib && $(MAKE) generate 2>&1 | tee -a generation_results.log
	@cd cli && $(MAKE) generate 2>&1 | tee -a generation_results.log
	@$(GO) generate -run mockgen ./...  2>&1 | tee -a generation_results.log
	@if [ -s ./generation_results.log ]; then printf "%b" "$(WARN_COLOR)$(WARN_STRING) Warning generating code, if RICE related, then is a false warning !$(NO_COLOR)\n";fi;

test: begin # Run unit tests
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running unit tests, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(GO) test -v ${PKG_LIST} 2>&1 > test_results.log || true
	@go2xunit -input test_results.log -output xunit_tests.xml || true
	@if [ -s ./test_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) tests FAILED ! Take a look at ./test_results.log $(NO_COLOR)\n";else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. TESTS PASSED ! $(NO_COLOR)\n";fi;

test-light: begin # Run unit tests
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running unit tests (with restrictions), $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(GO) test -v ${TESTABLE_PKG_LIST} 2>&1 > test_results.log || true
	@go2xunit -input test_results.log -output xunit_tests.xml || true
	@if [ -s ./test_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) tests (with restrictions) FAILED ! Take a look at ./test_results.log $(NO_COLOR)\n";exit 1;else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. TESTS PASSED ! $(NO_COLOR)\n";fi;

vet-light: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running vet checks (with restrictions), $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(GO) vet ${TESTABLE_PKG_LIST} 2>&1 | tee vet_results.log
	@if [ -s ./vet_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) vet (with restrictions) FAILED !$(NO_COLOR)\n";exit 1;else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. NO PROBLEMS DETECTED ! $(NO_COLOR)\n";fi;

err: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running errcheck, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@errcheck ${TESTABLE_PKG_LIST} 2>&1 | grep -v _test | grep -v test_ | tee err_results.log
	@if [ -s ./err_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) errcheck (with restrictions) FAILED !$(NO_COLOR)\n";exit 1;else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. NO PROBLEMS DETECTED ! $(NO_COLOR)\n";fi;

err-light: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running errcheck (with restrictions), $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@errcheck ${TESTABLE_PKG_LIST} 2>&1 | grep -v defer | grep -v _test | grep -v test_ | tee err_results.log
	@if [ -s ./err_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) errcheck (with restrictions) FAILED !$(NO_COLOR)\n";exit 1;else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. NO PROBLEMS DETECTED ! $(NO_COLOR)\n";fi;

vet: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running vet checks, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(GO) vet ${PKG_LIST} 2>&1 | tee vet_results.log
	@if [ -s ./vet_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) vet FAILED !$(NO_COLOR)\n";exit 1;else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. NO PROBLEMS DETECTED ! $(NO_COLOR)\n";fi

lint: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running lint checks, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(GO) list ./... | grep -v /vendor/ | xargs -L1 golint

coverage: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Collecting coverage data, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(GO) test -v ${TESTABLE_PKG_LIST} -coverprofile=cover.out > coverage_results.log 2>&1 || true
	@$(GO) tool cover -html=cover.out -o cover.html || true

show-cov: begin
	@command -v firefox >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) You don't have firefox on PATH.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }
	@if [ -s ./cover.out ]; then $(GO) tool cover -html=cover.out -o cover.html || true;fi
	@if [ -s ./cover.html ]; then $(BROWSER) ./cover.html || true;fi

report: begin
	@printf "%b" "$(WARN_COLOR)$(WARN_STRING) Running in background, it takes time... when finished opens report in firefox , $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@printf "%b" "$(WARN_COLOR)$(WARN_STRING) You should keep in mind that results are pretty useless until we reach a reasonable amount of unit-tested code... ;) , $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@goreporter -p . -c 1 -e vendor > report_results.log 2>&1

logclean: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Cleaning logs... $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(RM) test_results.log || true
	@$(RM) coverage_results.log || true
	@$(RM) generation_results.log || true
	@$(RM) vet_results.log || true
	@$(RM) xunit_tests.xml || true
	@$(RM) cover.out || true
	@$(RM) cover.html || true

status: with_git
	@git remote update >/dev/null 2>&1
	@printf "%b" "$(WARN_COLOR)LOCAL BUILD STATUS:$(NO_COLOR)\n";
	@printf "%b" "$(NO_COLOR)  Build hash $(OK_COLOR)$(BUILD)$(GOLD_COLOR)$(NO_COLOR)\n";
	@printf "%b" "$(WARN_COLOR)";
	@if [ $(LOCAL) = $(REMOTE) ]; then echo "  Build Up-to-date"; elif [ $(LOCAL) = $(BASE) ]; then echo "  You are behind origin/develop"; elif [ $(REMOTE) = $(BASE) ]; then echo "  You have local commits NOT PUSHED to origin/develop"; else echo "  Build Diverged, you have to merge"; fi
	@printf "%b" "$(NO_COLOR)";

help: with_git
	@echo ''
	@git remote update >/dev/null 2>&1
	@printf "%b" "$(GOLD_COLOR) *************** SAFESCALE BUILD$(GOLD_COLOR) ****************$(NO_COLOR)\n";
	@echo ' If in doubt, try "make all"'
	@echo ''
	@printf "%b" "$(OK_COLOR)BUILD TARGETS:$(NO_COLOR)\n";
	@printf "%b" "  $(GOLD_COLOR)all          - Builds all binaries$(NO_COLOR)\n";
	@printf "%b" "$(NO_COLOR)";
	@echo '  help         - Prints this help message'
	@echo '  docs         - Runs godoc in background at port 6060.'
	@echo '                 Go to (http://localhost:6060/pkg/github.com/CS-SI/)'
	@echo '  install      - Copies all binaries to $(GOBIN)'
	@echo ''
	@printf "%b" "$(OK_COLOR)TESTING TARGETS:$(NO_COLOR)\n";
	@printf "%b" "$(NO_COLOR)";
	@echo '  lint         - Runs linter'
	@echo '  vet          - Runs all checks'
	@echo '  vet-light    - Runs all checks (with restrictions)'
	@echo '  err          - Looks for unhandled errors'
	@echo '  err-light    - Looks for unhandled errors (with restrictions)'
	@echo '  test         - Runs all tests'
	@echo '  test-light   - Runs all tests (with restrictions)'
	@echo '  coverage     - Collects coverage info from unit tests'
	@echo '  show-cov     - Displays coverage info in firefox'
	@echo '  report       - Generates and displays a report'
	@echo ''
	@printf "%b" "$(OK_COLOR)DEV TARGETS:$(NO_COLOR)\n";
	@printf "%b" "$(NO_COLOR)";
	@echo '  clean        - Removes files generated by build.'
	@echo '  depclean     - Rebuilds vendor dependencies'
	@echo '  logclean     - Removes log files generated by build.'
	@echo '  status       - Shows build status.'
	@echo ''
	@echo
