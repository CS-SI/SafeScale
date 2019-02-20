GO?=go

.PHONY:	generate

all:	generate

generate:
	@$(GO) generate ./...

vet:
	@$(GO) vet ./...

clean:
	@(cd aws && $(MAKE) $(@))
	@(cd cloudferro && $(MAKE) $(@))
	@(cd cloudwatt && $(MAKE) $(@))
	@(cd flexibleengine && $(MAKE) $(@))
	@(cd openstack && $(MAKE) $(@))
	@(cd opentelekom && $(MAKE) $(@))
	@(cd ovh && $(MAKE) $(@))
	@$(RM) ./mocks/*.go || true
