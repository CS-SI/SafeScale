GO?=go

.PHONY:	clean generate vet

generate:
	@(cd aws && $(MAKE) $(@))
	@(cd cloudferro && $(MAKE) $(@))
	@(cd cloudwatt && $(MAKE) $(@))
	@(cd flexibleengine && $(MAKE) $(@))
	@(cd openstack && $(MAKE) $(@))
	@(cd opentelekom && $(MAKE) $(@))
	@(cd ovh && $(MAKE) $(@))
	@(cd local && $(MAKE) $(@))
	@(cd erbc && $(MAKE) $(@))

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
	@(cd local && $(MAKE) $(@))
	@(cd erbc && $(MAKE) $(@))
	@$(RM) ./mocks/*.go || true
