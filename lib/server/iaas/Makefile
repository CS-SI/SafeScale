GO?=go

.PHONY:	clean generate vet

all: generate

generate:
	@(cd resources && $(MAKE) $(@))
	@(cd providers && $(MAKE) $(@))

vet:
	@$(GO) vet $(BUILD_TAGS) ./...

clean:
	@(cd resources && $(MAKE) $(@))
	@(cd stacks && $(MAKE) $(@))
	@(cd providers && $(MAKE) $(@))
	@$(RM) ./mocks/*.go || true
