GO?=go

.PHONY:	clean generate vet

all: generate

generate:
	@(cd abstract && $(MAKE) $(@))
	@(cd providers && $(MAKE) $(@))

vet:
	@$(GO) vet $(BUILD_TAGS) ./...

clean:
	@(cd abstract && $(MAKE) $(@))
	@(cd stacks && $(MAKE) $(@))
	@(cd providers && $(MAKE) $(@))
	@$(RM) ./mocks/*.go || true
