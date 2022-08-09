include ../../common.mk

.PHONY:	lib/frontend/cmdline lib/frontend/web clean vet

all:	lib/frontend/cmdline lib/frontend/web

vet:
	@$(GO) vet ./...

test:
	@$(GO) test $(RACE_CHECK_TEST) $(GO_TEST_TAGS) -timeout 900s -v ./... -p 1 $(TEST_COVERAGE_ARGS) 2>&1
	@(cd cmdline && $(MAKE) $(@))

lib/frontend/cmdline:
	@(cd cmdline && $(MAKE) all)

lib/frontend/web:
	@:

clean:
	@(cd cmdline && $(MAKE) clean)
