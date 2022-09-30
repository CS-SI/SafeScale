GO?=go

.PHONY:	clean generate vet

all: generate

generate: clean
	@(cd api && $(MAKE) $(@))
	@(cd objectstorage && $(MAKE) $(@))
	@(cd providers && $(MAKE) $(@))
	@(cd userdata && $(MAKE) $(@))
	@(cd stacks && $(MAKE) $(@))

vet:
	@$(GO) vet ./...

clean:
	@(cd api && $(MAKE) $(@))
	@(cd objectstorage && $(MAKE) $(@))
	@(cd providers && $(MAKE) $(@))
	@(cd userdata && $(MAKE) $(@))
	@(cd stacks && $(MAKE) $(@))
