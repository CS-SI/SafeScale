GO?=go

.PHONY:	clean generate vet

generate:
	@(cd cloudferro && $(MAKE) $(@))
	@(cd cloudwatt && $(MAKE) $(@))
	@(cd flexibleengine && $(MAKE) $(@))
	@(cd openstack && $(MAKE) $(@))
	@(cd opentelekom && $(MAKE) $(@))
	@(cd ovh && $(MAKE) $(@))
	@(cd local && $(MAKE) $(@))
	@(cd gcp && $(MAKE) $(@))

vet:
	@$(GO) vet ./...

clean:
	@(cd cloudferro && $(MAKE) $(@))
	@(cd cloudwatt && $(MAKE) $(@))
	@(cd flexibleengine && $(MAKE) $(@))
	@(cd openstack && $(MAKE) $(@))
	@(cd opentelekom && $(MAKE) $(@))
	@(cd ovh && $(MAKE) $(@))
	@(cd local && $(MAKE) $(@))
	@(cd gcp && $(MAKE) $(@))
	@$(RM) ./mocks/*.go || true
