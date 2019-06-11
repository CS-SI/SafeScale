GO?=go

.PHONY: clean generate retry vet

all: retry

retry:
	@(cd retry && $(MAKE) all)

generate:
	@$(GO) generate -run stringer ./...

vet:
	@$(GO) vet ./...

clean:
	@(find . | grep _string | xargs rm 2>/dev/null || true)

