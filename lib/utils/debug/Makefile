GO?=go

.PHONY: clean generate vet

all: generate

generate:
	@$(GO) generate -run stringer ./...
	@mkdir -p ./mocks || true
	@$(GO) generate -run minimock . >/dev/null 2>&1 || true

vet:
	@$(GO) vet ./...

clean:
	@(find . | grep _string | xargs rm 2>/dev/null || true)
	@$(RM) ./mocks/*.go || true
