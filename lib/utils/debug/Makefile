GO?=go

.PHONY: clean generate vet

all: generate

generate:
	@$(GO) generate -run stringer ./...

vet:
	@$(GO) vet ./...

clean:
	@(find . | grep _string | xargs rm 2>/dev/null || true)

