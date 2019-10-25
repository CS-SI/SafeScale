GO?=go

.PHONY: clean generate

all:
	@(cd gateway/client && $(MAKE) $@)
	@(cd gateway/daemon && $(MAKE) $@)

vet:
	@$(GO) vet ./...

generate:
	@(cd gateway/client && $(MAKE) all)
	@(cd gateway/daemon && $(MAKE) all)

clean:
	@(cd gateway/client && $(MAKE) $@)
	@(cd gateway/daemon && $(MAKE) $@)