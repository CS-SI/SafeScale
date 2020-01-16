GO?=go

.PHONY:	clean generate vet

generate: clean
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

all: generate
	@(cd cloudferro && $(MAKE) $(@))
	@(cd cloudwatt && $(MAKE) $(@))
	@(cd flexibleengine && $(MAKE) $(@))
	@(cd openstack && $(MAKE) $(@))
	@(cd opentelekom && $(MAKE) $(@))
	@(cd ovh && $(MAKE) $(@))
	@(cd local && $(MAKE) $(@))
	@(cd gcp && $(MAKE) $(@))

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
