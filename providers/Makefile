GO?=go

.PHONY:	generate api aws cloudwatt flexibleengine openstack opentelekom ovh userdata

all:	generate

generate:
	@$(GO) generate ./...

vet:
	@$(GO) vet ./...

clean:
	@(cd userdata && $(MAKE) $(@))
	@(cd aws && $(MAKE) $(@))
	@(cd enums && $(MAKE) $(@))
	@(cd api && $(MAKE) $@)
	@$(RM) ./mocks/*.go || true
