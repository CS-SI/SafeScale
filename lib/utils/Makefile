GO?=go

.PHONY: clean generate vet

all: generate

generate:
	@(mkdir -p mocks) || true
	@(mkdir -p data/mocks) || true
	@$(GO) generate -run stringer ./...
	@echo "package valid" > ./valid/consts.go
	@grep EmbeddedErrorStructName ./fail/errors.go >> ./valid/consts.go

vet:
	@$(GO) vet ./...

test:
	@$(GO) test $(RACE_CHECK_TEST) $(GO_TEST_TAGS) -timeout 900s -v ./... -p 1 $(TEST_COVERAGE_ARGS) 2>&1

clean:
	@(find . | grep _string | xargs rm 2>/dev/null || true)

