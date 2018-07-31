GO?=go
DIRECTORIES_ = $(sort $(dir $(wildcard */)))
DIRECTORIES = $(filter-out tests/ metadata/, $(DIRECTORIES_))

.PHONY:	api aws cloudwatt flexibleengine openstack opentelekom ovh userdata clean

all:	api aws cloudwatt flexibleengine openstack opentelekom ovh userdata

vet:
	@$(GO) vet
	@$(GO) vet ./tests

api:
	@(cd $@ && $(MAKE))

aws:	api
	@(cd $@ && $(MAKE))

cloudwatt:	api openstack
	@(cd $@ && $(MAKE))

flexibleengine:	api openstack
	@(cd $@ && $(MAKE))

opentelekom:	api flexibleengine
	@(cd $@ && $(MAKE))

openstack:	api
	@(cd $@ && $(MAKE))

ovh:	api openstack
	@(cd $@ && $(MAKE))

userdata:
	@(cd $@ && $(MAKE))

clean:
	@(for d in $(DIRECTORIES); do (cd $$d; $(MAKE) $@); done)
