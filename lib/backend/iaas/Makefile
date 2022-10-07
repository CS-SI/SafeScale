GO?=go

.PHONY:	clean generate vet

all: generate

generate: clean
	@$(GO) generate -run minimock ./...

vet:
	@$(GO) vet ./...

clean:
	@(cd api && $(MAKE) $(@))
	@(cd objectstorage && $(MAKE) $(@))
	@(cd providers && $(MAKE) $(@))
	@(cd userdata && $(MAKE) $(@))
	@(cd stacks && $(MAKE) $(@))
