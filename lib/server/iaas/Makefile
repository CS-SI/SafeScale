GO?=go

.PHONY:	clean generate vet

all: generate

generate: clean
	@mkdir -p mocks || true
	@$(GO) generate -run minimock . >/dev/null 2>&1 || true
	@(cd objectstorage && $(MAKE) $(@))
	@(cd providers && $(MAKE) $(@))
	@(cd userdata && $(MAKE) $(@))
	@(cd stacks && $(MAKE) $(@))

vet:
	@$(GO) vet ./...

clean:
	@(cd objectstorage && $(MAKE) $(@))
	@(cd providers && $(MAKE) $(@))
	@(cd userdata && $(MAKE) $(@))
	@(cd stacks && $(MAKE) $(@))
	@$(RM) ./mocks/*.go || true
