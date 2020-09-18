GO?=go

.PHONY:	clean generate vet

generate:
	@(cd cloudferro && $(MAKE) $(@))
	@(cd flexibleengine && $(MAKE) $(@))
	@(cd openstack && $(MAKE) $(@))
	@(cd opentelekom && $(MAKE) $(@))
	@(cd ovh && $(MAKE) $(@))
	@(cd local && $(MAKE) $(@))
	@(cd gcp && $(MAKE) $(@))
	@(cd aws && $(MAKE) $(@))
	@(cd ebrc && $(MAKE) $(@))

vet:
	@$(GO) vet $(BUILD_TAGS) ./...

clean:
	@(cd cloudferro && $(MAKE) $(@))
	@(cd flexibleengine && $(MAKE) $(@))
	@(cd openstack && $(MAKE) $(@))
	@(cd opentelekom && $(MAKE) $(@))
	@(cd ovh && $(MAKE) $(@))
	@(cd local && $(MAKE) $(@))
	@(cd gcp && $(MAKE) $(@))
	@(cd aws && $(MAKE) $(@))
	@(cd ebrc && $(MAKE) $(@))
	@$(RM) ./mocks/*.go || true
