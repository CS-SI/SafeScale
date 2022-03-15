ndef = $(if $(value $(1)),,$(error $(1) not set))

.DEFAULT_GOAL := help

.PHONY: default version
default: help ;

THIS_FILE := $(lastword $(MAKEFILE_LIST))

include ./common.mk

# Binaries generated
EXECS=cli/safescale/safescale$(EXT) cli/safescaled/safescaled$(EXT)
COVEREXECS=cli/safescale/safescale-cover$(EXT) cli/safescaled/safescaled-cover$(EXT)

# Code generation
STRINGER := golang.org/x/tools/cmd/stringer
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
GOENUM := github.com/abice/go-enum
GOWRAP := github.com/hexdigest/gowrap
MAINT := github.com/yagipy/maintidx/cmd/maintidx
IRETURN := github.com/butuzov/ireturn/cmd/ireturn

# CI tools
BATS := github.com/sstephenson/bats
GOJQ := github.com/itchyny/gojq/cmd/gojq
GRON := github.com/tomnomnom/gron
JSONTOML := github.com/pelletier/go-toml

# Default build tags
BUILD_TAGS = 
export BUILD_TAGS

TEST_COVERAGE_ARGS =
export TEST_COVERAGE_ARGS

all: logclean ground getdevdeps modclean sdk generate lib mintest cli minimock err vet semgrep style metalint
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Build, branch $$(git rev-parse --abbrev-ref HEAD) SUCCESSFUL $(NO_COLOR)\n";
	@git ls-tree --full-tree --name-only -r HEAD | grep \.go | xargs md5sum 2>/dev/null > sums.log || true
	@md5sum cli/safescaled/safescaled 2>/dev/null >> sums.log || true
	@md5sum cli/safescale/safescale 2>/dev/null >> sums.log || true

with-soft:
	@echo "go easy running semgrep"
	@$(eval CERR = "default")

ci: logclean ground getdevdeps mod sdk generate lib cli minimock err vet with-soft semgrep style metalint
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Build, branch $$(git rev-parse --abbrev-ref HEAD) SUCCESSFUL $(NO_COLOR)\n";

rawci: logclean ground getdevdeps mod sdk generate lib cli
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Build, branch $$(git rev-parse --abbrev-ref HEAD) SUCCESSFUL $(NO_COLOR)\n";

allcover: logclean ground getdevdeps mod sdk generate lib cli minimock err vet semgrep style metalint
	@(cd cli/safescale && $(MAKE) $(@))
	@(cd cli/safescaled && $(MAKE) $(@))
	@git ls-tree --full-tree --name-only -r HEAD | grep \.go | xargs md5sum 2>/dev/null > sums.log || true
	@md5sum cli/safescaled/safescaled 2>/dev/null >> sums.log || true
	@md5sum cli/safescale/safescale 2>/dev/null >> sums.log || true
	@md5sum cli/safescaled/safescaled-cover 2>/dev/null >> sums.log || true
	@md5sum cli/safescale/safescale-cover 2>/dev/null >> sums.log || true

version:
	@printf "%b" "$(VERSION)-$$(git rev-parse --abbrev-ref HEAD | tr \"/\" \"_\")";

release: logclean ground getdevdeps mod releasetags sdk generate lib cli test minimock err vet semgrep style metalint releasearchive
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Build for release, branch $$(git rev-parse --abbrev-ref HEAD) SUCCESSFUL $(NO_COLOR)\n";
	@git ls-tree --full-tree --name-only -r HEAD | grep \.go | xargs md5sum 2>/dev/null > sums.log || true
	@md5sum cli/safescaled/safescaled 2>/dev/null >> sums.log || true
	@md5sum cli/safescale/safescale 2>/dev/null >> sums.log || true

releaserc: logclean ground getdevdeps mod releasetags sdk generate lib cli minimock err vet style metalint releasearchive
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Build for rc, branch $$(git rev-parse --abbrev-ref HEAD) SUCCESSFUL $(NO_COLOR)\n";
	@git ls-tree --full-tree --name-only -r HEAD | grep \.go | xargs md5sum 2>/dev/null > sums.log || true
	@md5sum cli/safescaled/safescaled 2>/dev/null >> sums.log || true
	@md5sum cli/safescale/safescale 2>/dev/null >> sums.log || true

releasetags:
	@echo "settings go build tags for release"
	@$(eval BUILD_TAGS = "release,$(BUILD_TAGS)")

ifeq ($(OS),Windows_NT)
releasearchive:
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Creating release archive $(NO_COLOR)\n";
	@tar caf safescale-v$(VERSION)-$(shell $(GO) env GOOS)-$(shell $(GO) env GOARCH).tar.gz -C cli/safescale safescale.exe -C ../../cli/safescaled safescaled.exe
else
releasearchive:
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Creating release archive $(NO_COLOR)\n";
	@tar caf safescale-v$(VERSION)-$(shell $(GO) env GOOS)-$(shell $(GO) env GOARCH).tar.gz -C cli/safescale safescale -C ../../cli/safescaled safescaled
endif

with-coverage:
	@echo "settings go test coverage option"
	@$(eval TEST_COVERAGE_ARGS = "-coverprofile=cover.out")

checkbuild: begin
	@if [ ! -s ./sums.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) checkbuild FAILED, you have to run 'make all' first !$(NO_COLOR)\n";exit 1;fi;
ifeq ($(shell md5sum --status -c sums.log 2>/dev/null && echo 0 || echo 1 ),1)
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Fast Build assumes all dependencies are already there and code generation is also up to date $(NO_COLOR)\n";
	@(cd lib && $(MAKE) all)
	@(cd cli && $(MAKE) all)
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Fast Build, branch $$(git rev-parse --abbrev-ref HEAD) SUCCESSFUL $(NO_COLOR)\n";
	@git ls-tree --full-tree --name-only -r HEAD | grep \.go | xargs md5sum 2>/dev/null > sums.log || true
	@md5sum cli/safescaled/safescaled 2>/dev/null >> sums.log || true
	@md5sum cli/safescale/safescale 2>/dev/null >> sums.log || true
else
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Nothing to do $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
endif

common: begin ground getdevdeps mod sdk generate

versioncut:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Go version check$(NO_COLOR)\n";
	@(($(GO) version | grep go1.18) || ($(GO) version | grep go1.17) ||($(GO) version | grep go1.16)) || (printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) Minimum go version is 1.16 ! $(NO_COLOR)\n" && false);

begin: versioncut
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Build begins, branch $$(git rev-parse --abbrev-ref HEAD), commit $$(git log --format="%H" -n 1), go '$$($(GO) version)', protoc '$$(protoc --version)' ...$(NO_COLOR)\n";

mod:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading package dependencies..., $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@($(GO) mod download || true)
	@sleep 4
	@while [ $(ps -ef | grep "mod download") ] ; do \
		sleep 4 ; \
	done
	@($(GO) mod tidy || true)
	@($(GO) get google.golang.org/protobuf/reflect/protoreflect@v1.27.1 || true)
	@($(GO) get google.golang.org/protobuf/runtime/protoimpl@v1.27.1 || true)
	@($(GO) get google.golang.org/protobuf/types/known/emptypb@v1.27.1 || true)
	@($(GO) get google.golang.org/protobuf/types/known/timestamppb@v1.27.1 || true)
	@sleep 4
	@while [ $(ps -ef | grep "mod download") ] ; do \
		sleep 4 ; \
	done
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Finished downloading package dependencies..., $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";

cleancache:
	@($(GO) clean -cache -modcache -i -r &>/dev/null || true)

modclean: cleancache mod

debug:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Building with 'debug' flag$(NO_COLOR)\n";
	$(eval BUILD_TAGS = "debug,$(BUILD_TAGS)")

tunnel:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Building with 'tunnel' flag$(NO_COLOR)\n";
	$(eval BUILD_TAGS = "tunnel,$(BUILD_TAGS)")

alltests:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Building with 'alltests' flag$(NO_COLOR)\n";
	$(eval BUILD_TAGS = "alltests,$(BUILD_TAGS)")

with_git:
	@command -v git >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) git is required but it's not installed.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }

ground: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Testing tool prerequisites, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@command -v git >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) git is required but it's not installed.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }
	@command -v $(GO) >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) go is required but it's not installed.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }
	@command -v protoc >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) protoc is required but it's not installed.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }
	@cp ./hooks/pre-commit ./.git/hooks/pre-commit > /dev/null || true
	@chmod u+x ./.git/hooks/pre-commit > /dev/null || true

#CI dependencies
cideps: begin ground
	@$(WHICH) gojq > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading gojq...$(NO_COLOR)\n"; \
		$(GO) install $(GOJQ)@v0.12.6 &>/dev/null || true; \
	fi
	@$(WHICH) gron > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading gron...$(NO_COLOR)\n";
		$(GO) install $(GRON)@v0.6.1 &>/dev/null || true; \
	fi
	@$(WHICH) jsontoml > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading jsontoml...$(NO_COLOR)\n"; \
		$(GO) install $(JSONTOML)/cmd/jsontoml@v1.9.4 &>/dev/null || true; \
	fi
	@$(WHICH) tomljson > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading tomljson...$(NO_COLOR)\n"; \
		$(GO) install $(JSONTOML)/cmd/tomljson@v1.9.4 &>/dev/null || true; \
	fi

batscheck: begin
	@if [ ! -s ./helpers/bin/bats ]; then \
		printf "%b" "$(ERROR_COLOR)$(INFO_STRING) Cannot run bats tests: bats is not installed, use the target installbats to do it.  Aborting.$(NO_COLOR)\n" >&2; exit 1; \
	fi

installbats: begin ground
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Installing bats...$(NO_COLOR)\n"
	@mkdir -p ./helpers/tmp || true
	@if [ ! -s ./helpers/bin/bats ]; then git clone https://github.com/sstephenson/bats.git ./helpers/tmp;./helpers/tmp/install.sh ./helpers;rm -rf ./helpers/tmp; fi

bashtest: begin batscheck
	@(cd lib && $(MAKE) $(@))

trivycheck: begin
	@if [ ! -s ./helpers/bin/trivy ]; then \
		printf "%b" "$(ERROR_COLOR)$(INFO_STRING) Cannot run trivy tests: trivy is not installed, use the target installtrivy to do it.  Aborting.$(NO_COLOR)\n" >&2; exit 1; \
	fi

installtrivy: begin ground
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Installing trivy...$(NO_COLOR)\n"
	@mkdir -p ./helpers/tmp || true
	@if [ ! -s ./helpers/bin/trivy ]; then curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | bash -s -- -b `pwd`/helpers/bin v0.19.2;rm -rf ./helpers/tmp; fi

trivyreport: begin ground trivycheck
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Generating trivy report in background (trivy-report.log) ...$(NO_COLOR)\n"
	@find . | grep yml | xargs grep FROM | awk {'print $$3'} | sort | uniq | grep : | xargs -I _ ./helpers/bin/trivy image -s CRITICAL _ > trivy-report.log &

coverdeps: begin ground
	@$(WHICH) cover > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading cover...\n" && $(GO) install $(COVER)@v0.1.0 &>/dev/null || true; \
	fi
	@sleep 2
	@$(WHICH) covertool > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading covertool...\n" && $(GO) install $(COVERTOOL) &>/dev/null || true; \
	fi
	@sleep 2
	@$(WHICH) go2xunit > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading go2xunit...\n" && $(GO) install $(XUNIT)@v1.4.10 &>/dev/null || true; \
	fi
	@sleep 2

getdevdeps: begin ground
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Getting dependencies. $(NO_COLOR)\n";
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Testing prerequisites, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@sleep 2
	@$(WHICH) protoc-gen-go > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading protoc-gen-go...\n"; \
		$(GO) install github.com/golang/protobuf/protoc-gen-go@v1.3.2 &>/dev/null; \
	fi
	@sleep 2
	@$(WHICH) protoc-gen-go-grpc > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading protoc-gen-go-grpc...\n"; \
		$(GO) install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.1.0 &>/dev/null; \
	fi
	@sleep 2
	@$(WHICH) minimock > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading minimock...\n"; \
		$(GO) get -d $(MINIMOCK)@v3.0.10 &>/dev/null || true; \
		$(GO) install $(MINIMOCK)@v3.0.10 &>/dev/null || true; \
	fi
	@sleep 2
	@$(WHICH) errcheck > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading errcheck...\n"; \
		$(GO) install $(ERRCHECK)@v1.6.0 &>/dev/null || true; \
	fi
	@sleep 2
	@$(WHICH) goconvey > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading convey...\n"; \
		$(GO) install $(CONVEY)@v1.6.6 &>/dev/null || true; \
	fi
	@sleep 2
	@$(WHICH) golint > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading linter...\n"; \
		$(GO) install $(LINTER)@v0.0.0-20201208152925-83fdc39ff7b5 &>/dev/null || true; \
	fi
	@sleep 2
	@$(WHICH) stringer > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading stringer...\n"; \
		$(GO) install $(STRINGER)@v0.1.9 &>/dev/null || true; \
	fi
	@sleep 2
	@$(WHICH) go-enum > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading go-enum...\n"; \
		$(GO) install $(GOENUM)@v0.3.11 &>/dev/null || true; \
	fi
	@sleep 2
	@$(WHICH) gowrap > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading gowrap...\n"; \
		$(GO) install $(GOWRAP)/cmd/gowrap@v1.2.2 &>/dev/null || true; \
	fi
	@sleep 2
	@$(WHICH) ruleguard > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading ruleguard...\n"; \
		$(GO) install $(RULES)@v0.3.15 &>/dev/null || true; \
		$(GO) get -d $(RULES_DSL)@v0.3.17 &>/dev/null || true; \
	fi
	@sleep 2
	@$(WHICH) maintidx > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading maintidx...\n"; \
		$(GO) install $(MAINT)@v1.0.0 &>/dev/null || true; \
	fi
	@sleep 2
	@$(WHICH) ireturn > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Downloading ireturn...\n"; \
		$(GO) install $(IRETURN)@v0.1.1 &>/dev/null || true; \
	fi
	@sleep 2
	@$(WHICH) golangci-lint > /dev/null; if [ $$? -ne 0 ]; then \
		printf "%b" "$(OK_COLOR)$(INFO_STRING) Installing golangci...\n" || true; \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell $(GO) env GOPATH)/bin v1.42.1 || true; \
	fi
	@sleep 5

ensure: common
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Code generation, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";

unmerged:
	@$(WHICH) git > /dev/null && git grep -r "<<<<<" -- "*.*" && printf "%b" "$(ERR_COLOR)$(INFO_STRING) Unmerged content...\n" && exit 1 || true

sdk: getdevdeps unmerged
	@(cd lib && $(MAKE) $(@))

force_sdk_python: sdk
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

zipsources:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Creating a tar.gz file safescale-$$VERSION-$$(git rev-parse --abbrev-ref HEAD | sed 's#/#\_#g')-src.tar.gz with the sources..., $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(git archive --format tar.gz --output safescale-$$VERSION-$$(git rev-parse --abbrev-ref HEAD | sed 's#/#\_#g')-src.tar.gz master)

pack: zipsources

mrproper: clean
	@(git clean -xdf -e .idea -e vendor -e .vscode || true)

install: removebins
	@($(CP) -f $(EXECS) $(GOPATH)/bin)
	@($(CP) -f $(COVEREXECS) $(GOPATH)/bin > /dev/null 2>&1 || true)

removebins:
	@# Big Sur on ARM M1 processor requires all code to be validly signed; so removal of existing files is necessary
	@(for i in $(foreach v,$(EXECS),$(notdir $v)); do rm -f "$(GOPATH)/bin/$$i" || : ; done)
	@(for i in $(foreach v,$(COVEREXECS),$(notdir $v)); do rm -f "$(GOPATH)/bin/$$i" || : ; done)

installci:
	@(mkdir -p $(CIBIN) || true)
	@($(CP) -f $(EXECS) $(CIBIN) || true)
	@($(CP) -f $(COVEREXECS) $(CIBIN) > /dev/null 2>&1 || true)
	@($(CP) -f go.mod go.sum $(CIBIN) > /dev/null 2>&1 || true)
	@($(CP) -f lib/protocol/python3/safescale_pb2.py lib/protocol/python3/safescale_pb2_grpc.py $(CIBIN) > /dev/null 2>&1 || true)

godocs:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running godocs in background, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(godoc -http=:6060 &)

convey:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running goconvey in background, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd lib && cd utils && goconvey -port 8082 . &)

conveystop:
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Stopping goconvey in background, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(ps -ef | grep goconvey | grep -v grep | grep 8082 | awk {'print $$2'} | xargs kill -9 || true)

generate: sdk
	@sleep 2
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running code generation, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(RM) ./generation_results.log || true
	@$(GO) generate -run stringer ./... 2>&1 | $(TEE) -a generation_results.log || true
	@cd cli && $(MAKE) gensrc 2>&1 | $(TEE) -a generation_results.log || true
	@cd lib && $(MAKE) gensrc 2>&1 | $(TEE) -a generation_results.log || true
	@cd lib && $(MAKE) generate 2>&1 | $(TEE) -a generation_results.log || true
	@cd cli && $(MAKE) generate 2>&1 | $(TEE) -a generation_results.log || true
	@$(GO) generate ./... >> generation_results.log 2>&1 || true
	@if [ -s ./generation_results.log ]; then printf "%b" "$(WARN_COLOR)$(WARN_STRING) Warnings generating code !$(NO_COLOR)\n";fi;

mintest: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running minimal unit tests subset, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(RM) ./test_results.log || true
	@$(GO) test $(RACE_CHECK_TEST) $(GO_TEST_TAGS) -timeout 480s -v ./lib/utils/concurrency/... -p 2 $(TEST_COVERAGE_ARGS) 2>&1 > test_results.log || true
	@$(CP) ./cover.out ./cover.tmp 2>/dev/null || true
	@$(GO) test $(RACE_CHECK_TEST) $(GO_TEST_TAGS) -timeout 480s -v ./lib/utils/fail/... -p 2 $(TEST_COVERAGE_ARGS) 2>&1 >> test_results.log || true
	@$(TAIL) -n +2 ./cover.out >> ./cover.tmp 2>/dev/null || true
	@$(GO) test $(RACE_CHECK_TEST) $(GO_TEST_TAGS) -timeout 480s -v ./lib/utils/retry/... -p 2 $(TEST_COVERAGE_ARGS) 2>&1 >> test_results.log || true
	@$(TAIL) -n +2 ./cover.out >> ./cover.tmp 2>/dev/null || true
	@$(GO) test $(RACE_CHECK_TEST) $(GO_TEST_TAGS) -timeout 480s -v ./lib/utils/data/... -p 2 $(TEST_COVERAGE_ARGS) 2>&1 >> test_results.log || true
	@$(TAIL) -n +2 ./cover.out >> ./cover.tmp 2>/dev/null || true
	@$(GO) test $(RACE_CHECK_TEST) $(GO_TEST_TAGS) -timeout 900s -v ./lib/server/resources/... -p 1 $(TEST_COVERAGE_ARGS) 2>&1 >> test_results.log || true
	@$(TAIL) -n +2 ./cover.out >> ./cover.tmp 2>/dev/null || true
	@$(MV) ./cover.tmp ./cover.out 2>/dev/null || true
	@if [ -s ./test_results.log ] && grep FAIL ./test_results.log 2>&1 > /dev/null; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) minimal tests FAILED ! Take a look at ./test_results.log $(NO_COLOR)\n";else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. TESTS PASSED ! $(NO_COLOR)\n";fi;
	@if [ -s ./test_results.log ] && grep FAIL ./test_results.log; then exit 1;else $(RM) ./test_results.log;fi;

precommittest: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running precommit unit tests subset, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(RM) ./test_results.log || true
	@PCT=1 $(GO) test $(RACE_CHECK_TEST) $(GO_TEST_TAGS) -timeout 480s -v ./lib/utils/concurrency/... -p 2 $(TEST_COVERAGE_ARGS) 2>&1 > test_results.log || true
	@$(CP) ./cover.out ./cover.tmp 2>/dev/null || true
	@PCT=1 $(GO) test $(RACE_CHECK_TEST) $(GO_TEST_TAGS) -timeout 480s -v ./lib/utils/fail/... -p 2 $(TEST_COVERAGE_ARGS) 2>&1 >> test_results.log || true
	@$(TAIL) -n +2 ./cover.out >> ./cover.tmp 2>/dev/null || true
	@PCT=1 $(GO) test $(RACE_CHECK_TEST) $(GO_TEST_TAGS) -timeout 480s -v ./lib/utils/retry/... -p 2 $(TEST_COVERAGE_ARGS) 2>&1 >> test_results.log || true
	@$(TAIL) -n +2 ./cover.out >> ./cover.tmp 2>/dev/null || true
	@PCT=1 $(GO) test $(RACE_CHECK_TEST) $(GO_TEST_TAGS) -timeout 480s -v ./lib/utils/data/... -p 2 $(TEST_COVERAGE_ARGS) 2>&1 >> test_results.log || true
	@$(TAIL) -n +2 ./cover.out >> ./cover.tmp 2>/dev/null || true
	@PCT=1 $(GO) test $(RACE_CHECK_TEST) $(GO_TEST_TAGS) -timeout 900s -v ./lib/server/resources/... -p 1 $(TEST_COVERAGE_ARGS) 2>&1 >> test_results.log || true
	@$(TAIL) -n +2 ./cover.out >> ./cover.tmp 2>/dev/null || true
	@$(MV) ./cover.tmp ./cover.out 2>/dev/null || true
	@if [ -s ./test_results.log ] && grep FAIL ./test_results.log 2>&1 > /dev/null; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) minimal tests FAILED ! Take a look at ./test_results.log $(NO_COLOR)\n";else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. TESTS PASSED ! $(NO_COLOR)\n";fi;
	@if [ -s ./test_results.log ] && grep FAIL ./test_results.log; then exit 1;else $(RM) ./test_results.log;fi;

test: begin coverdeps # Run unit tests
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running unit tests, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(RM) ./test_results.log || true
	@$(GO) clean -testcache
	@$(GO) test $(RACE_CHECK_TEST) $(GO_TEST_TAGS) -timeout 900s -v ./lib/utils/... -p 1 $(TEST_COVERAGE_ARGS) 2>&1 > test_results.log || true
	@$(CP) ./cover.out ./cover.tmp 2>/dev/null || true
	@$(GO) test $(RACE_CHECK_TEST) $(GO_TEST_TAGS) -timeout 900s -v ./lib/server/resources/... -p 1 $(TEST_COVERAGE_ARGS) 2>&1 >> test_results.log || true
	@$(TAIL) -n +2 ./cover.out >> ./cover.tmp 2>/dev/null || true
	@$(MV) ./cover.tmp ./cover.out 2>/dev/null || true
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
	@$(GO) list ./... 2>&1 | grep -v mock | grep -v rules | grep -v cli | xargs errcheck -asserts | grep -v test | grep -v .pb. | grep -v nolint | $(TEE) err_results.log
	@if [ -s ./err_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) errcheck FAILED !$(NO_COLOR)\n";exit 1;else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. NO PROBLEMS DETECTED ! $(NO_COLOR)\n";fi;

vet: begin generate
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running vet checks, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(GO) list ./... | grep -v mock | grep -v rules | grep -v cli | xargs $(GO) vet | $(TEE) vet_results.log
	@if [ -s ./vet_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) vet FAILED !$(NO_COLOR)\n";exit 1;else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. NO PROBLEMS DETECTED ! $(NO_COLOR)\n";fi

semgrep: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running semgrep checks with '$(CERR)' ruleset, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@($(GO) version | grep go1.18) && (printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) Semgrep don't work with go1.18 yet ! $(NO_COLOR)\n" && false) || true;
	@$(GO) get -d $(RULES_DSL)@v0.3.17 &>/dev/null || true;
	@($(WHICH) ruleguard > /dev/null || (echo "ruleguard not installed in your system" && exit 1))
ifeq ($(shell md5sum --status -c sums.log 2>/dev/null && echo 0 || echo 1 ),1)
	@$(RM) semgrep_results.log || true
	@ruleguard -c=0 -rules build/rules/ruleguard.rules.$(CERR).go ./... 2>&1 | tr '\n' '\0' | xargs -0 -n2 | grep -v nolint | grep -v _test.go | grep -v mock | grep -v .pb. | awk 'NF' | $(TEE) semgrep_results.log
	@ruleguard -c=0 -rules build/rules/ruleguard.rules.json.go ./... 2>&1 | tr '\n' '\0' | xargs -0 -n2 | grep -v nolint | grep -v mock | grep -v _test.go | grep -v .pb. | awk 'NF' | $(TEE) -a semgrep_results.log
	@ruleguard -c=0 -rules build/rules/ruleguard.rules.locks.go ./... 2>&1 | tr '\n' '\0' | xargs -0 -n2 | grep -v defer | grep -v nolint | grep -v mock | grep -v _test.go | grep -v .pb. | awk 'NF' | $(TEE) -a semgrep_results.log
	@if [ -s ./semgrep_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) semgrep FAILED, look at semgrep_results.log !$(NO_COLOR)\n";exit 1;else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. NO PROBLEMS DETECTED ! $(NO_COLOR)\n";fi
else
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Nothing to do $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
endif

minimock: begin generate
	@$(GO) generate -run minimock ./... > /dev/null 2>&1 | $(TEE) -a generation_results.log

beta: begin
	@$(GO) install golang.org/dl/go1.18beta1@latest
	@echo "go begins"
	@$(eval GO = "go1.18beta1")
	@$(GO) download
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) go version: $$($(GO) version), $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd lib && $(MAKE) all)
	@(cd cli && $(MAKE) all)
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running errcheck, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(GO) list ./... 2>&1 | grep -v mock | grep -v rules | grep -v cli | grep -v .pb. | grep -v nolint | grep -v _test.go | xargs errcheck | grep -v test | awk 'NF' | $(TEE) err_results.log
	@if [ -s ./err_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) errcheck FAILED !$(NO_COLOR)\n";exit 1;else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. NO PROBLEMS DETECTED ! $(NO_COLOR)\n";fi;
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Fast Build, branch $$(git rev-parse --abbrev-ref HEAD) SUCCESSFUL $(NO_COLOR)\n";

metalint: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running metalint checks, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@($(WHICH) golangci-lint > /dev/null || (echo "golangci-lint not installed in your system" && exit 1))
ifeq ($(shell md5sum --status -c sums.log 2>/dev/null && echo 0 || echo 1 ),1)
	@$(RM) metalint_results.log || true
	@golangci-lint --color never --timeout=16m --no-config --disable=unused --disable=goconst --disable=maligned --enable=unparam --enable=deadcode --disable=gocyclo --enable=varcheck --enable=staticcheck --enable=structcheck --disable=typecheck --enable=errcheck --enable=ineffassign --enable=interfacer --enable=unconvert --enable=gosec --enable=megacheck --enable=gocritic --enable=dogsled --disable=funlen --disable=gochecknoglobals --enable=depguard run ./... 2>/dev/null | tr '\n' '\0' | xargs -0 -n3 | grep -v nolint | grep -v _test.go | grep -v .pb. | grep -v "\s*^\s*" | $(TEE) metalint_results.log
	@if [ -s ./metalint_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) metalint FAILED, look at metalint_results.log !$(NO_COLOR)\n";exit 1;else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. NO PROBLEMS DETECTED ! $(NO_COLOR)\n";fi
else
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Nothing to do $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
endif

newissues: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running checks on modified files, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@($(WHICH) golangci-lint > /dev/null || (echo "golangci-lint not installed in your system" && exit 1))
ifeq ($(shell md5sum --status -c sums.log 2>/dev/null && echo 0 || echo 1 ),1)
	@if [ ! -s ./sums.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) broken FAILED, you have to run 'make all' first !$(NO_COLOR)\n";exit 1;fi;
	@md5sum --ignore-missing -w -c sums.log 2>&1 | grep FAILED | tr ':' ' ' | awk {'print $$1'} | xargs -L1 golangci-lint run 2>/dev/null  | tr '\n' '\0' | xargs -0 -n3 | grep -v nolint | grep -v _test.go | grep -v .pb. | grep -v typecheck
else
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Nothing to do $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
endif

style: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running style checks, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@($(WHICH) golangci-lint > /dev/null || (echo "golangci-lint not installed in your system" && exit 1))
ifeq ($(shell md5sum --status -c sums.log 2>/dev/null && echo 0 || echo 1 ),1)
	@$(RM) style_results.log || true
	@golangci-lint --color never --timeout=10m --no-config --disable=unused --disable=goconst --disable=gocyclo --enable=errcheck --enable=stylecheck --disable=typecheck --enable=deadcode --enable=revive --enable=gocritic --enable=staticcheck --enable=gosimple --enable=govet --enable=ineffassign --enable=varcheck run ./... 2>/dev/null | tr '\n' ' ' | tr "^" '\0' | xargs -0 -n1 | grep -v _test.go | grep -v nolint | grep -v .pb. | grep -v typecheck | awk 'NF' | $(TEE) style_results.log
	@if [ -s ./style_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) style FAILED, look at style_results.log !$(NO_COLOR)\n";exit 1;else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. NO PROBLEMS DETECTED ! $(NO_COLOR)\n";fi
else
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Nothing to do $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
endif

maint: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running maint checks, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@($(WHICH) maintidx > /dev/null || (echo "maintidx not installed in your system" && exit 1))
ifeq ($(shell md5sum --status -c sums.log 2>/dev/null && echo 0 || echo 1 ),1)
	@$(RM) maint_results.log || true
	@maintidx ./... 2>&1 | $(TEE) maint_results.log
	@if [ -s ./maint_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) maint FAILED, look at maint_results.log !$(NO_COLOR)\n";exit 1;else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. NO PROBLEMS DETECTED ! $(NO_COLOR)\n";fi
else
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Nothing to do $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
endif

badpractices: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running bad practices checks, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@($(WHICH) ireturn > /dev/null || (echo "ireturn not installed in your system" && exit 1))
ifeq ($(shell md5sum --status -c sums.log 2>/dev/null && echo 0 || echo 1 ),1)
	@$(RM) practices_results.log || true
	@ireturn ./... 2>&1 | grep -v mock_ | grep -v fail.Error | $(TEE) practices_results.log
	@if [ -s ./practices_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) maint FAILED, look at practices_results.log !$(NO_COLOR)\n";exit 1;else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. NO PROBLEMS DETECTED ! $(NO_COLOR)\n";fi
else
	@printf "%b" "$(OK_COLOR)$(OK_STRING) Nothing to do $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
endif

warnings: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Running warnings checks, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@($(WHICH) golangci-lint > /dev/null || (echo "golangci-lint not installed in your system" && exit 1))
	@$(RM) warnings_results.log || true
	@golangci-lint --color never --timeout=16m run ./... 2>/dev/null | tr '\n' ' ' | sed -e "s/\^/\n/g" | grep -v nolint | grep -v rangeValCopy | grep -v json.camel | grep -v magic.numbers | grep -v _test.go | grep -v .pb. | $(TEE) warnings_results.log
	@if [ -s ./warnings_results.log ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) warnings FAILED, look at warnings_results.log !$(NO_COLOR)\n";exit 1;else printf "%b" "$(OK_COLOR)$(OK_STRING) CONGRATS. NO PROBLEMS DETECTED ! $(NO_COLOR)\n";fi

show-cov: begin
	@command -v $(BROWSER) >/dev/null 2>&1 || { printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) You don't have $(BROWSER) on PATH.  Aborting.$(NO_COLOR)\n" >&2; exit 1; }
	@if [ ! -s ./cover.out ]; then printf "%b" "$(ERROR_COLOR)$(ERROR_STRING) show-cov FAILED, You have to run coverage first !$(NO_COLOR)\n";exit 1;fi
	@if [ -s ./cover.out ]; then $(GO) tool cover -html=cover.out -o cover.html || true;fi
	@if [ -s ./cover.html ]; then $(BROWSER) ./cover.html || true;fi

logclean: begin
	@printf "%b" "$(OK_COLOR)$(INFO_STRING) Cleaning logs... $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@$(RM) sums.log || true
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
	@echo '                 Go to (http://localhost:6060/pkg/github.com/CS-SI/SafeScale/)'
	@echo '  install      - Copies all binaries to $(GOPATH)/bin'
	@echo ''
	@printf "%b" "$(OK_COLOR)TESTING TARGETS:$(NO_COLOR)\n";
	@printf "%b" "$(NO_COLOR)";
	@echo '  metalint     - Runs golangci-lint'
	@echo '  style        - Runs golangci-lint focusing on style issues'
	@echo '  vet          - Runs all checks'
	@echo '  err          - Looks for unhandled errors'
	@echo '  test         - Runs all unit tests'
	@echo '  convey       - Runs goconvey in lib/utils dir'
	@echo '  show-cov     - Displays coverage info in firefox'
	@echo ''
	@printf "%b" "$(OK_COLOR)DEV TARGETS:$(NO_COLOR)\n";
	@printf "%b" "$(NO_COLOR)";
	@echo '  clean        - Removes files generated by build.'
	@echo '  logclean     - Removes log files generated by build.'
	@echo
