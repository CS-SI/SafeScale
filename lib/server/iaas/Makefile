GO?=go

.PHONY:	clean generate vet

all: generate

generate:
	@(cd resources && $(MAKE) $(@))
	@(cd providers && $(MAKE) $(@))

vet:
	@$(GO) vet ./...

clean:
	@(cd resources && $(MAKE) $(@))
	@(cd stacks && $(MAKE) $(@))
	@(cd providers && $(MAKE) $(@))
	@$(RM) ./mocks/*.go || true
