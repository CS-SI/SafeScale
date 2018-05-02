all: openstack

.PHONY: api openstack clean

api:
	@(cd api && go generate)

openstack: 
	@(cd openstack && go generate)

clean:
	$(cd openstack && $(MAKE) $@)
	$(cd brokerd && $(MAKE) $@)
	$(cd broker && $(MAKE) $@)
	$(cd cluster && $(MAKE) $@)

