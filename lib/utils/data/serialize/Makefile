GO?=go

.PHONY: clean generate vet

all: generate

generate:
	@mkdir -p ./mocks || true

vet:
	@$(GO) vet ./...

test:
	@$(GO) test $(RACE_CHECK_TEST) $(GO_TEST_TAGS) -timeout 900s -v ./... -p 1 $(TEST_COVERAGE_ARGS) 2>&1

clean:
	@$(RM) ./mocks/mock_*.go || true

