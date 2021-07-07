ndef = $(if $(value $(1)),,$(error $(1) not set))

.DEFAULT_GOAL := help

.PHONY: default
default: help ;

include ./common.mk

# Binaries generated
EXECS=cli/safescale/safescale$(EXT) cli/safescaled/safescaled$(EXT)
COVEREXECS=cli/safescale/safescale-cover$(EXT) cli/safescaled/safescaled-cover$(EXT)

# Code generation
STRINGER := golang.org/x/tools/cmd/stringer
RICE := github.com/GeertJohan/go.rice
PROTOC := github.com/golang/protobuf
PROTOBUF := github.com/golang/protobuf/protoc-gen-go

# Build tools
CONVEY := github.com/smartystreets/goconvey
MINIMOCK := github.com/gojuno/minimock/v3/cmd/minimock
COVER := golang.org/x/tools/cmd/cover
LINTER := golang.org/x/lint/golint
ERRCHECK := github.com/kisielk/errcheck
XUNIT := github.com/tebeka/go2xunit
COVERTOOL := github.com/dlespiau/covertool
RULES := github.com/quasilyte/go-ruleguard/cmd/ruleguard
RULES_DSL := github.com/quasilyte/go-ruleguard/dsl
GOGREP := mvdan.cc/gogrep

# CI tools
GOJQ := github.com/itchyny/gojq/cmd/gojq
GRON := github.com/tomnomnom/gron
JSONTOML := github.com/pelletier/go-toml

# Default build tags
BUILD_TAGS = 
export BUILD_TAGS

#all: logclean ground getdevdeps mod sdk generate lib mintest cli minimock err vet
all: logclean ground getdevdeps mod sdk generate lib cli minimock err vet
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Build SUCCESSFUL $(NO_COLOR)\n";

allcover: all
	@(cd cli/safescale && $(MAKE) $(@))
	@(cd cli/safescaled && $(MAKE) $(@))

#release: logclean ground getdevdeps mod releasetags sdk generate lib safemintest cli minimock err vet releasearchive
release: logclean ground getdevdeps mod releasetags sdk generate lib cli minimock err vet releasearchive
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Build for release SUCCESSFUL $(NO_COLOR)\n";

releasetags:
	@echo "settings go build tags for release"
	@$(eval BUILD_TAGS = "release,$(BUILD_TAGS)")

releasearchive:
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Creating release archive $(NO_COLOR)\n";
	@tar --strip-components=2 -zcf safescale-$(VERSION)-$(shell $(GO) env GOOS)-$(shell $(GO) env GOARCH).tar.gz cli/safescale/safescale cli/safescaled/safescaled

fastall: begin
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Fast Build assumes all dependencies are already there and code generation is also up to date $(NO_COLOR)\n";
	@(cd lib && $(MAKE) all)
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running minimal unit tests subset, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(GO) test $(RACE_CHECK_TEST) -timeout 120s -v ./lib/utils/concurrency/... > test_results.log || (printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) minimal tests FAILED ! Take a look at ./test_results.log $(NO_COLOR)\n";grep FAIL ./test_results.log;exit 1)
	@$(RM) ./test_results.log || true
	@(cd cli && $(MAKE) all)
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running errcheck, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(GO) list ./... | grep -v mock | grep -v cli | xargs errcheck | $(TEE) err_results.log
	@if [ -s ./err_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) errcheck FAILED !$(NO_COLOR)\n";exit 1;else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. NO PROBLEMS DETECTED ! $(NO_COLOR)\n";fi;
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Fast Build SUCCESSFUL $(NO_COLOR)\n";

common: begin ground getdevdeps mod sdk generate

versioncut:
	@(($(GO) version | grep go1.16) || ($(GO) version | grep go1.15)) || (printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) Minimum go version is 1.15 ! $(NO_COLOR)\n" && false);

begin: versioncut
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Build begins...$(NO_COLOR)\n";

mod:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading package dependencies..., $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@($(GO) mod download)

libvirt:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Libvirt driver enabled$(NO_COLOR)\n";
	@$(WHICH) lsmod > /dev/null; if [ $$? -ne 0 ]; then \
		@printf "%b" "$(WARN_COLOR)$(WARN_STRING) Libvirt not available in this platform !\n"; exit 1;\
	fi
	@systemctl status libvirtd.service >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) libvirt is required but it's not installed.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }
	@lsmod | grep kvm >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) kvm is required but it's not installed.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }
	@grep -E '^flags.*(vmx|svm)' /proc/cpuinfo >/dev/null 2>&1 && \
	if [ $$? -eq 0 ]; then \
		printf "%b" "$(OK_COLOR)$(OK_STRING) Hardware acceleration is available!\n"; \
	else \
		printf "%b" "$(WARN_COLOR)$(WARN_STRING) Hardware acceleration is NOT available!\n"; \
	fi
	$(eval BUILD_TAGS = "libvirt,$(BUILD_TAGS)") \
	@printf "%b" "$(WARN_COLOR)$(WARN_STRING) Libvirt doesn't work on develop branch right now!\n"; exit 1;

debug:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Building with 'debug' flag$(NO_COLOR)\n";
	$(eval BUILD_TAGS = "debug,$(BUILD_TAGS)")

vcloud:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Building with 'vcloud' flag$(NO_COLOR)\n";
	$(eval BUILD_TAGS = "vcloud,$(BUILD_TAGS)")

alltests:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Building with 'alltests' flag$(NO_COLOR)\n";
	$(eval BUILD_TAGS = "alltests,$(BUILD_TAGS)")

with_git:
	@command -v git >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) git is required but it's not installed.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }

ground:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Testing tool prerequisites, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@command -v git >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) git is required but it's not installed.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }
	@command -v $(GO) >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) go is required but it's not installed.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }
	@command -v protoc >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) protoc is required but it's not installed.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }

cideps: begin ground
	@$(WHICH) gojq > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading gojq...\n" && $(GO) get $(GOJQ)@v0.12.3 &>/dev/null || true; \
	fi
	@$(WHICH) gron > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading gron...\n" && $(GO) get $(GRON)@v0.6.1 &>/dev/null || true; \
	fi
	@$(WHICH) jsontoml > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading jsontoml...\n" && $(GO) get $(JSONTOML)/cmd/jsontoml@v1.9.0 &>/dev/null || true; \
	fi
	@$(WHICH) tomljson > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading tomljson...\n" && $(GO) get $(JSONTOML)/cmd/tomljson@v1.9.0 &>/dev/null || true; \
	fi

coverdeps: begin ground
	@$(WHICH) cover > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading cover...\n" && $(GO) install $(COVER)@v0.1.0 &>/dev/null || true; \
	fi
	@$(WHICH) covertool > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading covertool...\n" && $(GO) install $(COVERTOOL) &>/dev/null || true; \
	fi
	@$(WHICH) go2xunit > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading go2xunit...\n" && $(GO) install $(XUNIT)@v1.4.10 &>/dev/null || true; \
	fi

getdevdeps: begin ground
ifneq ($(STRICT),1)
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Installing with version tags. $(NO_COLOR)\n";
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Testing prerequisites, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(WHICH) rice > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading rice...$(NO_COLOR)\n" && $(GO) get $(RICE)@v1.0.2 &>/dev/null && $(GO) install $(RICE)/rice@v1.0.2 &>/dev/null; \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Installing rice module...$(NO_COLOR)\n" && $(GO) mod download github.com/GeertJohan/go.rice@v1.0.2 &>/dev/null || true; \
    fi
	@sleep 2
	@$(WHICH) rice > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading rice...$(NO_COLOR)\n" && $(GO) get $(RICE)@v1.0.2 &>/dev/null && $(GO) install $(RICE)/rice@v1.0.2 &>/dev/null; \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Installing rice module...$(NO_COLOR)\n" && $(GO) mod download github.com/GeertJohan/go.rice@v1.0.2 &>/dev/null || true; \
	fi
	@sleep 2
	@$(WHICH) protoc-gen-go > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading protoc-gen-go...\n" && $(GO) get github.com/golang/protobuf/protoc-gen-go@v1.3.2 &>/dev/null && $(GO) install github.com/golang/protobuf/protoc-gen-go@v1.3.2 &>/dev/null; \
	fi
	@$(WHICH) minimock > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading minimock...\n" && $(GO) get $(MINIMOCK)@v3.0.9 &>/dev/null || true; \
		$(GO) install $(MINIMOCK)@v3.0.9 &>/dev/null || true; \
	fi
	@$(WHICH) errcheck > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading errcheck...\n" && $(GO) get $(ERRCHECK)@v1.6.0 &>/dev/null || true; \
		$(GO) install $(ERRCHECK)@v1.6.0 &>/dev/null || true; \
	fi
	@$(WHICH) goconvey > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading convey...\n" && $(GO) get $(CONVEY)@v1.6.4 &>/dev/null || true; \
		$(GO) install $(CONVEY)@v1.6.4 &>/dev/null || true; \
	fi
	@$(WHICH) golint > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading linter...\n" && $(GO) get $(LINTER)@v0.0.0-20201208152925-83fdc39ff7b5 &>/dev/null || true; \
		$(GO) install $(LINTER)@v0.0.0-20201208152925-83fdc39ff7b5 &>/dev/null || true; \
	fi
	@$(WHICH) ruleguard > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading ruleguard...\n" && $(GO) get $(RULES)@v0.3.4 && $(GO) get $(RULES_DSL)@v0.3.6 &>/dev/null || true; \
		$(GO) install $(RULES)@v0.3.4 &>/dev/null || true; \
	fi
	@$(WHICH) gogrep > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading gogrep...\n" && $(GO) get $(GOGREP)@v0.0.0-20210331191051-e50df5835157 &>/dev/null || true; \
		$(GO) install $(GOGREP)@v0.0.0-20210331191051-e50df5835157 &>/dev/null || true; \
	fi
	@$(WHICH) stringer > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading stringer...\n" && $(GO) get $(STRINGER)@v0.1.0 &>/dev/null || true; \
		$(GO) install $(STRINGER)@v0.1.0 &>/dev/null || true; \
	fi
	@$(WHICH) golangci-lint > /dev/null; if [ $$? -ne 0 ]; then \
    	printf "%b" "$(OK_COLOR)$(INFO_STRING) Installing golangci...\n" || true; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell $(GO) env GOPATH)/bin v1.26.0 || true; \
	fi
else
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Installing without version tags. $(NO_COLOR)\n";
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Testing prerequisites, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(WHICH) rice > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading rice...$(NO_COLOR)\n" && $(GO) get $(RICE)@v1.0.2 &>/dev/null && $(GO) install $(RICE)/rice &>/dev/null; \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Installing rice module...$(NO_COLOR)\n" && $(GO) mod download github.com/GeertJohan/go.rice &>/dev/null; \
	fi
	@sleep 2
	@$(WHICH) rice > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading rice...$(NO_COLOR)\n" && $(GO) get $(RICE)@v1.0.2 &>/dev/null && $(GO) install $(RICE)/rice &>/dev/null; \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Installing rice module...$(NO_COLOR)\n" && $(GO) mod download github.com/GeertJohan/go.rice &>/dev/null; \
	fi
	@sleep 2
	@$(WHICH) protoc-gen-go > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading protoc-gen-go...\n" && $(GO) get github.com/golang/protobuf/protoc-gen-go@v1.3.2 &>/dev/null && $(GO) install github.com/golang/protobuf/protoc-gen-go &>/dev/null; \
	fi
	@$(WHICH) minimock > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading minimock...\n" && $(GO) get $(MINIMOCK)@v3.0.9 &>/dev/null || true; \
		$(GO) install $(MINIMOCK) &>/dev/null || true; \
	fi
	@$(WHICH) errcheck > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading errcheck...\n" && $(GO) get $(ERRCHECK)@v1.6.0 &>/dev/null || true; \
		$(GO) install $(ERRCHECK) &>/dev/null || true; \
	fi
	@$(WHICH) goconvey > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading convey...\n" && $(GO) get $(CONVEY)@v1.6.4 &>/dev/null || true; \
		$(GO) install $(CONVEY) &>/dev/null || true; \
	fi
	@$(WHICH) golint > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading linter...\n" && $(GO) get $(LINTER)@v0.0.0-20201208152925-83fdc39ff7b5 &>/dev/null || true; \
		$(GO) install $(LINTER) &>/dev/null || true; \
	fi
	@$(WHICH) stringer > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading stringer...\n" && $(GO) get $(STRINGER)@v0.1.0 &>/dev/null || true; \
		$(GO) install $(STRINGER) &>/dev/null || true; \
	fi
	@$(WHICH) golangci-lint > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Installing golangci...\n" || true; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell $(GO) env GOPATH)/bin v1.26.0 || true; \
	fi
	@git checkout go.mod
endif

ensure: common
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Code generation, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	
sdk: getdevdeps
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
	@(for i in $(EXECS); do echo $$i; $(RM) -f "$(GOPATH)/bin/$$i"; done)
	@($(CP) -f $(EXECS) $(GOPATH)/bin || true)
	@($(CP) -f $(COVEREXECS) $(GOPATH)/bin > /dev/null 2>&1 || true)

installci:
	@(mkdir -p $(CIBIN) || true)
	@($(CP) -f $(EXECS) $(CIBIN) || true)
	@($(CP) -f $(COVEREXECS) $(CIBIN) > /dev/null 2>&1 || true)

godocs:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running godocs in background, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(godoc -http=:6060 &)

convey:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running goconvey in background, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(goconvey -port 8082 . &)

conveystop:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Stopping goconvey in background, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(ps -ef | grep goconvey | grep -v grep | grep 8082 | awk {'print $2'} | xargs kill -9 || true)

generate: sdk
	@sleep 5
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running code generation, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(RM) ./generation_results.log || true
	@$(GO) generate -run stringer ./... 2>&1 | $(TEE) -a generation_results.log
	@cd cli && $(MAKE) gensrc 2>&1 | $(TEE) -a generation_results.log
	@cd lib && $(MAKE) gensrc 2>&1 | $(TEE) -a generation_results.log
	@cd lib && $(MAKE) generate 2>&1 | $(TEE) -a generation_results.log
	@cd cli && $(MAKE) generate 2>&1 | $(TEE) -a generation_results.log
	@$(GO) generate ./... >> generation_results.log 2>&1 || true
	@if [ -s ./generation_results.log ]; then printf "%b" "$(WARN_COLOR)$(WARN_STRING) Warnings generating code !$(NO_COLOR)\n";fi;

mintest: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running minimal unit tests subset, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(RM) ./test_results.log || true
	@$(GO) test $(RACE_CHECK_TEST) -timeout 480s -v ./lib/utils/concurrency/... 2>&1 > test_results.log || true
	@if [ -s ./test_results.log ] && grep FAIL ./test_results.log 2>&1 > /dev/null; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) minimal tests FAILED ! Take a look at ./test_results.log $(NO_COLOR)\n";else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. TESTS PASSED ! $(NO_COLOR)\n";fi;
	@if [ -s ./test_results.log ] && grep FAIL ./test_results.log; then exit 1;else $(RM) ./test_results.log;fi;

safemintest: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running minimal unit tests subset, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(RM) ./test_results.log || true
	@$(GO) test $(RACE_CHECK_TEST) -timeout 480s -v ./lib/utils/concurrency/... -p 1 2>&1 > test_results.log || true
	@if [ -s ./test_results.log ] && grep FAIL ./test_results.log 2>&1 > /dev/null; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) minimal tests FAILED ! Take a look at ./test_results.log $(NO_COLOR)\n";else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. TESTS PASSED ! $(NO_COLOR)\n";fi;
	@if [ -s ./test_results.log ] && grep FAIL ./test_results.log; then exit 1;else $(RM) ./test_results.log;fi;

test: begin # Run unit tests
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running unit tests, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(RM) ./test_results.log || true
	@$(GO) test $(RACE_CHECK_TEST) -timeout 900s -v ./... > test_results.log || true
	@go2xunit -input test_results.log -output xunit_tests.xml || true
	@if [ -s ./test_results.log ] && grep FAIL ./test_results.log; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) tests FAILED ! Take a look at ./test_results.log $(NO_COLOR)\n";else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. TESTS PASSED ! $(NO_COLOR)\n";fi;

gofmt: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running gofmt checks, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@if [ -n "$$($(GOFMT) -d .)" ]; then \
		"$$($(GOFMT) -d .)" \
		echo "-- gofmt check failed"; \
		false; \
	fi

err: begin generate
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running errcheck, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(GO) list ./... | grep -v mock | grep -v rules | grep -v cli | xargs errcheck | $(TEE) err_results.log
	@if [ -s ./err_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) errcheck FAILED !$(NO_COLOR)\n";exit 1;else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. NO PROBLEMS DETECTED ! $(NO_COLOR)\n";fi;

vet: begin generate
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running vet checks, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(GO) list ./... | grep -v mock | grep -v rules | grep -v cli | xargs $(GO) vet | $(TEE) vet_results.log
	@if [ -s ./vet_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) vet FAILED !$(NO_COLOR)\n";exit 1;else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. NO PROBLEMS DETECTED ! $(NO_COLOR)\n";fi

semgrep: begin generate
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running semgrep checks, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@ruleguard -c=0 -rules build/rules/ruleguard.rules.$(CERR).go ./... | $(TEE) semgrep_results.log
	@if [ -s ./semgrep_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) semgrep FAILED !$(NO_COLOR)\n";exit 1;else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. NO PROBLEMS DETECTED ! $(NO_COLOR)\n";fi

minimock: begin generate
	@$(GO) generate -run minimock ./... > /dev/null 2>&1 | $(TEE) -a generation_results.log

metalint: begin generate
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running metalint checks, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@($(WHICH) golangci-lint > /dev/null || (echo "golangci-lint not installed in your system" && exit 1))
	@$(GO) list ./... | cut -c 28- | grep -v mocks | grep -v test | grep -v cli | xargs golangci-lint --color never --enable=unused --enable=unparam --enable=deadcode --enable=gocyclo --enable=varcheck --enable=staticcheck --enable=structcheck --enable=typecheck --enable=maligned --enable=errcheck --enable=ineffassign --enable=interfacer --enable=unconvert --enable=goconst --enable=gosec --enable=megacheck --enable=gocritic --enable=depguard --enable=dogsled --enable=funlen --enable=gochecknoglobals run || true

metalint-mini: begin generate
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running metalint checks, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@($(WHICH) golangci-lint > /dev/null || (echo "golangci-lint not installed in your system" && exit 1))
	@$(GO) list ./... | cut -c 28- | grep -v mocks | grep -v test | grep -v cli | xargs golangci-lint --color never--enable=deadcode --enable=staticcheck --enable=structcheck --enable=typecheck --enable=errcheck --enable=ineffassign --enable=interfacer --enable=unconvert --enable=megacheck --enable=gocritic --enable=depguard --enable=dogsled run || true

metalint-full: begin generate
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running metalint checks, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@($(WHICH) golangci-lint > /dev/null && golangci-lint --color never --enable=unused --enable=unparam --enable=deadcode --enable=gocyclo --enable=varcheck --enable=staticcheck --enable=structcheck --enable=typecheck --enable=maligned --enable=errcheck --enable=ineffassign --enable=interfacer --enable=unconvert --enable=goconst --enable=gosec --enable=megacheck --enable=gocritic --enable=depguard run --enable=dogsled --enable=funlen --enable=gochecknoglobals ./... || true) || echo "golangci-lint not installed in your system"

style: begin generate gofmt
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running style checks, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@($(WHICH) golangci-lint > /dev/null || (echo "golangci-lint not installed in your system" && exit 1))
	@$(GO) list ./... | cut -c 28- | grep -v mocks | grep -v cli | xargs golangci-lint --color never --enable=errcheck --enable=stylecheck --enable=deadcode --enable=golint --enable=gocritic --enable=staticcheck --enable=gosimple --enable=govet --enable=ineffassign --enable=varcheck run || true

style-full: begin generate gofmt
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running style checks, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@($(WHICH) golangci-lint > /dev/null && golangci-lint --color never --enable=errcheck --enable=stylecheck --enable=deadcode --enable=golint --enable=gocritic --enable=staticcheck --enable=gosimple --enable=govet --enable=ineffassign --enable=varcheck run ./... || true) || echo "golangci-lint not installed in your system"

coverage: begin generate
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Collecting coverage data, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(GO) test $(RACE_CHECK_TEST) -timeout 900s -v ./... -coverprofile=cover.out > coverage_results.log 2>&1 || true
	@$(GO) tool cover -html=cover.out -o cover.html || true

show-cov: begin generate
	@command -v firefox >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) You don't have firefox on PATH.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }
	@if [ -s ./cover.out ]; then $(GO) tool cover -html=cover.out -o cover.html || true;fi
	@if [ -s ./cover.html ]; then $(BROWSER) ./cover.html || true;fi

logclean: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Cleaning logs... $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(RM) *_results.log || true
	@$(RM) xunit_tests.xml || true
	@$(RM) cover.out || true
	@$(RM) cover.html || true

help: with_git
	@echo ''
	@printf "%b" "$(GOLD_COLOR) *************** SAFESCALE BUILD$(GOLD_COLOR) ****************$(NO_COLOR)\n";
	@echo ' If in doubt, try "make all"'
	@echo ''
	@printf "%b" "$(OK_COLOR)BUILD TARGETS:$(NO_COLOR)\n";
	@printf "%b" "  $(GOLD_COLOR)all          - Builds all binaries$(NO_COLOR)\n";
	@printf "%b" "$(NO_COLOR)";
	@echo '  help         - Prints this help message'
	@echo '  godocs       - Runs godoc in background at port 6060.'
	@echo '                 Go to (http://localhost:6060/pkg/github.com/CS-SI/)'
	@echo '  install      - Copies all binaries to $(GOPATH)/bin'
	@echo ''
	@printf "%b" "$(OK_COLOR)TESTING TARGETS:$(NO_COLOR)\n";
	@printf "%b" "$(NO_COLOR)";
	@echo '  metalint     - Runs golangci-lint'
	@echo '  style        - Runs golangci-lint focusing on style issues'
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
	@echo '  logclean     - Removes log files generated by build.'
	@echo
