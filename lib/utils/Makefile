GO?=go

.PHONY: clean generate vet

all: generate

generate:
	@mkdir -p ./mocks || true
	@echo "package valid" > ./valid/consts.go
	@grep EmbeddedErrorStructName ./fail/errors.go >> ./valid/consts.go
	@$(GO) generate -run stringer . >/dev/null || true
	@$(GO) generate -run minimock . >/dev/null || true
	@(cd concurrency && make $@)
	@(cd cli && make $@)
	@(cd data && make $@)
	@(cd debug && make $@)
	@(cd fail && make $@)
	@(cd temporal && make $@)
	@(cd retry && make $@)

vet:
	@$(GO) vet ./...

test:
	@$(GO) test $(RACE_CHECK_TEST) $(GO_TEST_TAGS) -timeout 900s -v ./... -p 1 $(TEST_COVERAGE_ARGS) 2>&1

clean:
	@(find . | grep _string | xargs rm 2>/dev/null || true)
	@(cd concurrency && make $@)
	@(cd cli && make $@)
	@(cd data && make $@)
	@(cd debug && make $@)
	@(cd fail && make $@)
	@(cd temporal && make $@)

