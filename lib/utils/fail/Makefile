GO?=go

.PHONY: clean generate vet

all: generate

generate:
	@mkdir -p ./mocks || true
	@$(GO) generate -run minimock . >/dev/null || true

vet:
	@$(GO) vet ./...

clean:
	@$(RM) ./mocks/mock_*.go || true
