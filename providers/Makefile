DIRECTORIES_ = $(sort $(dir $(wildcard */)))
DIRECTORIES = $(filter-out tests/, $(DIRECTORIES_))

all:	api aws cloudwatt flexibleengine openstack ovh

.PHONY:	api aws cloudwatt flexibleengine openstack ovh clean

api:
	@(cd $@ && $(MAKE))

aws:	api
	@(cd $@ && $(MAKE))

cloudwatt:	api openstack
	@(cd $@ && $(MAKE))

flexibleengine:	api openstack
	@(cd $@ && $(MAKE))

openstack:	api
	@(cd $@ && $(MAKE))

ovh:	api openstack
	@(cd $@ && $(MAKE))

clean:
	@(for d in $(DIRECTORIES); do (cd $$d; $(MAKE) $@); done)


