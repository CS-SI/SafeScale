GO?=go

.PHONY: clean generate vet

all: generate

generate:
	@(mkdir -p mocks) || true
	@(mkdir -p data/mocks) || true
	@$(GO) generate -run stringer ./...

vet:
	@$(GO) vet ./...

test:
	@$(GO) test $(RACE_CHECK_TEST) ./...

clean:
	@(find . | grep _string | xargs rm 2>/dev/null || true)

