GO?=go

.PHONY: clean generate vet

all: generate

generate:
	@mkdir -p ./mocks || true
	@$(GO) generate -run stringer ./... >/dev/null 2>&1 || true

vet:
	@$(GO) vet ./...

clean:
	@$(RM) ./mocks/mock_*.go || true
