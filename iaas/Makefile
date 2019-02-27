GO?=go

.PHONY:	generate

all:	generate

generate:
	@$(GO) generate ./...

vet:
	@$(GO) vet ./...

clean:
	@(cd resources && $(MAKE) $(@))
	@(cd stacks && $(MAKE) $(@))
	@(cd providers && $(MAKE) $(@))
	@$(RM) ./mocks/*.go || true
