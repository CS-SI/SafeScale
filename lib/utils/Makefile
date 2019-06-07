GO?=go

.PHONY: clean generate retry vet

all: retry

retry:
	@(cd retry && $(MAKE) all)

generate:
	@(cd retry && $(MAKE) $(@))

vet:
	@$(GO) vet ./...

clean:
	@(cd retry && $(MAKE) $(@))

