GO?=go

.PHONY:	clean generate vet

all: generate

minimock: generate

generate: clean
	@mkdir -p mocks || true
	@$(GO) generate ./... || true
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
	@$(RM) ./mocks/mock_*.go || true
