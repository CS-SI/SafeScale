GO?=go

.PHONY:	generate

all:	generate

generate:
	@$(GO) generate ./...

vet:
	@$(GO) vet ./...

clean:
	@(cd api && $(MAKE) $@)
	@(cd aws && $(MAKE) $(@))
	@(cd enums && $(MAKE) $(@))
	@(cd model && $(MAKE) $(@))
	@(cd userdata && $(MAKE) $(@))
	@$(RM) ./mocks/*.go || true
