GO?=go

.PHONY: clean generate vet

all: generate

generate:
	@mkdir -p ./mocks || true

vet:
	@$(GO) vet ./...

clean:
	@$(RM) ./mocks/mock_*.go || true
