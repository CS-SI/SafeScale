GO?=go

.PHONY:	generate

all:	generate

generate:
	@$(GO) generate ./...

vet:
	@$(GO) vet ./...

clean:
	@(cd aws && $(MAKE) $(@))
	@(cd huaweicloud && $(MAKE) $(@))
	@(cd openstack && $(MAKE) $(@))
	@(cd libvirt && $(MAKE) $(@))
	@$(RM) ./mocks/*.go || true
