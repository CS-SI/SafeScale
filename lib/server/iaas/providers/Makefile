GO?=go

#.PHONY:	all clean generate vet
.PHONY:	clean vet

generate: clean
	@(mkdir -p mocks) || true
	@(mkdir -p ../mocks) || true
	@$(GO) generate -run minimock . > /dev/null 2>&1
#all: generate
#	@(cd cloudferro && $(MAKE) $(@))
#	@(cd flexibleengine && $(MAKE) $(@))
#	@(cd openstack && $(MAKE) $(@))
#	@(cd opentelekom && $(MAKE) $(@))
#	@(cd ovh && $(MAKE) $(@))
#	@(cd local && $(MAKE) $(@))
#	@(cd gcp && $(MAKE) $(@))
#
#generate: clean
#	@(cd cloudferro && $(MAKE) $(@))
#	@(cd flexibleengine && $(MAKE) $(@))
#	@(cd openstack && $(MAKE) $(@))
#	@(cd opentelekom && $(MAKE) $(@))
#	@(cd ovh && $(MAKE) $(@))
#	@(cd local && $(MAKE) $(@))
#	@(cd gcp && $(MAKE) $(@))

vet:
	@$(GO) vet ./...

clean:
	@$(RM) ./mocks/*.go || true
#	@(cd gcp && $(MAKE) $(@))
#	@(cd cloudferro && $(MAKE) $(@))
#	@(cd flexibleengine && $(MAKE) $(@))
#	@(cd openstack && $(MAKE) $(@))
#	@(cd opentelekom && $(MAKE) $(@))
#	@(cd ovh && $(MAKE) $(@))
#	@(cd local && $(MAKE) $(@))
