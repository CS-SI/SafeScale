include ../../../common.mk

.PHONY: clean generate vet

all: generate

generate:
	@(mkdir -p ./mocks) || true
	@$(GO) generate -run minimock . >/dev/null 2>&1 || true
	@(cd cache && $(MAKE) $@)
	@(cd observer && $(MAKE) $@)
	@(cd serialize && $(MAKE) $@)

vet:
	@$(GO) vet ./...

test:
	@$(GO) test $(RACE_CHECK_TEST) $(GO_TEST_TAGS) -timeout 900s -v ./... -p 1 $(TEST_COVERAGE_ARGS) 2>&1

clean:
	@$(RM) ./mocks/* || true

