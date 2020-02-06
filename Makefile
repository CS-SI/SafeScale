ndef = $(if $(value $(1)),,$(error $(1) not set))

.DEFAULT_GOAL := help

.PHONY: default
default: help ;

#ROOTDIR:=$(shell ROOTDIR='$(ROOTDIR)' bash -c "dirname $(realpath $(lastword $(MAKEFILE_LIST)))")
#export ROOTDIR

include ./common.mk

# Binaries generated
EXECS=cli/safescale/safescale cli/safescale/safescale-cover cli/safescaled/safescaled cli/safescaled/safescaled-cover cli/perform/perform cli/perform/perform-cover cli/scanner/scanner

# List of files
PKG_FILES := $(shell find . \( -path ./vendor -o -path ./Godeps \) -prune -o -type f -name '*.go' -print | grep -v version.go | grep -v gomock_reflect_ | grep -v cluster/mocks )
# List of packages
PKG_LIST := $(shell $(GO) list ./... | grep -v lib/security/ | grep -v lib/system/firewall/ | grep -v /vendor/)
# List of packages alt
PKG_LIST_ALT := $(shell find . -type f -name '*.go' | grep -v lib/security/ | grep -v lib/system/firewall/ | grep -v gomock_reflect_ | grep -v cluster/mocks | grep -v stacks/mocks | grep -v cloudwatt |xargs -I {} dirname {} | uniq )
# List of packages to test
TESTABLE_PKG_LIST := $(shell $(GO) list ./... | grep -v lib/security/ | grep -v lib/system/firewall/ | grep -v sandbox)


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
ERRCHECK := github.com/kisielk/errcheck
XUNIT := github.com/tebeka/go2xunit
COVERTOOL := github.com/dlespiau/covertool
GOVENDOR := github.com/kardianos/govendor
GOLANGCI := github.com/golangci/golangci-lint/cmd/golangci-lint

DEVDEPSLIST := $(RICE) $(PROTOBUF) $(COVER) $(XUNIT) $(COVERTOOL)  $(GOVENDOR)
NEWDEVDEPSLIST := $(STRINGER) $(GOLANGCI) $(MOCKGEN) $(LINTER) $(CONVEY) $(ERRCHECK)

BUILD_TAGS = ""
export BUILD_TAGS

all: begin ground getdevdeps ensure generate lib cli err vet
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Build SUCCESSFUL $(NO_COLOR)\n";

common: begin ground getdevdeps ensure generate

versioncut:
	@(($(GO) version | grep go1.12) || ($(GO) version | grep go1.13) || ($(GO) version | grep go1.14)) || (printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) Minimum go version is 1.12 ! $(NO_COLOR)\n" && /bin/false);

begin: versioncut
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
	@which rice go2xunit cover covertool govendor > /dev/null; if [ $$? -ne 0 ]; then \
    	$(GO) get -u $(RICE) $(COVER) $(XUNIT) $(GOVENDOR) $(COVERTOOL) &>/dev/null || true; \
    fi
	@which protoc-gen-go > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading protoc-gen-go...\n" && $(GO) get github.com/golang/protobuf/protoc-gen-go@v1.3.2 &>/dev/null || true; \
	fi
	@which mockgen > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading mockgen...\n" && $(GO) get -u  $(MOCKGEN) &>/dev/null || true; \
	fi
	@which errcheck > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading errcheck...\n" && $(GO) get -u  $(ERRCHECK) &>/dev/null || true; \
	fi
	@which goconvey > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading convey...\n" && $(GO) get -u  $(CONVEY) &>/dev/null || true; \
	fi
	@which golint > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading linter...\n" && $(GO) get -u  $(LINTER) &>/dev/null || true; \
	fi
	@which stringer > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading stringer...\n" && $(GO) get -u  $(STRINGER) &>/dev/null || true; \
	fi
	@which golangci-lint > /dev/null; if [ $$? -ne 0 ]; then \
		$(GO) get -u  $(GOLANGCI) &>/dev/null || true; \
	fi

ensure:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Checking versions, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";

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

mrproper: clean
	@(git clean -xdf -e .idea -e vendor -e .vscode || true)

install:
	@($(CP) -f $(EXECS) $(GOBIN) || true)

installci:
	@(mkdir -p $(CIBIN) || true)
	@($(CP) -f $(EXECS) $(CIBIN) || true)

godocs:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running godocs in background, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(godoc -http=:6060 &)

convey:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running goconvey in background, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd lib/utils && goconvey -port 8082 &)

conveystop:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Stopping goconvey in background, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(ps -ef | grep goconvey | grep 8082 | awk {'print $2'} | xargs kill -9 || true)

depclean: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Cleaning vendor and redownloading deps, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@($(GO) mod download)

generate: begin # Run generation
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running code generation, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@rm -f ./generation_results.log || true
	@cd lib && $(MAKE) generate 2>&1 | tee -a generation_results.log
	@cd cli && $(MAKE) generate 2>&1 | tee -a generation_results.log
	@$(GO) generate -run mockgen ./...  2>&1 | tee -a generation_results.log
	@if [ -s ./generation_results.log ]; then printf "%b" "$(WARN_COLOR)$(WARN_STRING) Warning generating code, if RICE related, then is a false warning !$(NO_COLOR)\n";fi;

test: begin generate # Run unit tests
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running unit tests, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(GO) test -v ${PKG_LIST_ALT} 2>&1 > test_results.log || true
	@go2xunit -input test_results.log -output xunit_tests.xml || true
	@if [ -s ./test_results.log ] && grep FAIL ./test_results.log; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) tests FAILED ! Take a look at ./test_results.log $(NO_COLOR)\n";else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. TESTS PASSED ! $(NO_COLOR)\n";fi;

gofmt: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running gofmt checks, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@if [ -n "$$($(GOFMT) -d $(PKG_FILES))" ]; then \
		"$$($(GOFMT) -d $(PKG_FILES))" \
		echo "-- gofmt check failed"; \
		/bin/false; \
	fi

err: begin generate
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running errcheck, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@errcheck $(PKG_LIST_ALT) 2>&1 | tee err_results.log
	@if [ -s ./err_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) errcheck FAILED !$(NO_COLOR)\n";exit 1;else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. NO PROBLEMS DETECTED ! $(NO_COLOR)\n";fi;

vet: begin generate
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running vet checks, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(GO) vet ${PKG_LIST_ALT} 2>&1 | tee vet_results.log
	@if [ -s ./vet_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) vet FAILED !$(NO_COLOR)\n";exit 1;else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. NO PROBLEMS DETECTED ! $(NO_COLOR)\n";fi

lint: begin generate
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running lint checks, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@golint ./... | grep -v vendor | grep -v test | grep -v Test | grep -v enum\. | grep -v version\.go || true

metalint: begin generate
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running metalint checks, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(which golangci-lint > /dev/null && golangci-lint --color never --disable-all --enable=unused --enable=unparam --enable=deadcode --enable=gocyclo --enable=varcheck --enable=staticcheck --enable=structcheck --enable=typecheck --enable=maligned --enable=errcheck --enable=ineffassign --enable=interfacer --enable=unconvert --enable=goconst --enable=gosec --enable=megacheck --enable=gocritic --enable=depguard run --enable=dogsled --enable=funlen --enable=gochecknoglobals ./... || true) || echo "golangci-lint not installed in your system"

style: begin generate gofmt
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running style checks, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(which golangci-lint > /dev/null && golangci-lint --color never --disable-all --enable=errcheck --enable=stylecheck --enable=deadcode --enable=golint --enable=gocritic --enable=staticcheck --enable=gosimple --enable=govet --enable=ineffassign --enable=varcheck run ./... || true) || echo "golangci-lint not installed in your system"

coverage: begin generate
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Collecting coverage data, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(GO) test -v ${TESTABLE_PKG_LIST} -coverprofile=cover.out > coverage_results.log 2>&1 || true
	@$(GO) tool cover -html=cover.out -o cover.html || true

show-cov: begin generate
	@command -v firefox >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) You don't have firefox on PATH.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }
	@if [ -s ./cover.out ]; then $(GO) tool cover -html=cover.out -o cover.html || true;fi
	@if [ -s ./cover.html ]; then $(BROWSER) ./cover.html || true;fi

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
	@echo '  godocs       - Runs godoc in background at port 6060.'
	@echo '                 Go to (http://localhost:6060/pkg/github.com/CS-SI/)'
	@echo '  install      - Copies all binaries to $(GOBIN)'
	@echo ''
	@printf "%b" "$(OK_COLOR)TESTING TARGETS:$(NO_COLOR)\n";
	@printf "%b" "$(NO_COLOR)";
	@echo '  lint         - Runs linter'
	@echo '  metalint     - Runs golangci-lint'
	@echo '  vet          - Runs all checks'
	@echo '  err          - Looks for unhandled errors'
	@echo '  test         - Runs all unit tests'
	@echo '  convey       - Runs goconvey in lib dir'
	@echo '  coverage     - Collects coverage info from unit tests'
	@echo '  show-cov     - Displays coverage info in firefox'
	@echo ''
	@printf "%b" "$(OK_COLOR)DEV TARGETS:$(NO_COLOR)\n";
	@printf "%b" "$(NO_COLOR)";
	@echo '  clean        - Removes files generated by build.'
	@echo '  depclean     - Rebuilds vendor dependencies'
	@echo '  logclean     - Removes log files generated by build.'
	@echo '  status       - Shows build status.'
	@echo ''
	@echo
