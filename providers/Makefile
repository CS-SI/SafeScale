GO?=go
DIRECTORIES_ = $(sort $(dir $(wildcard */)))
DIRECTORIES = $(filter-out tests/ metadata/, $(DIRECTORIES_))

.PHONY:	api aws cloudwatt flexibleengine openstack opentelekom ovh clean

all:	api aws cloudwatt flexibleengine openstack opentelekom ovh vet

vet:
	@$(GO) vet
	@$(GO) vet ./tests

api:
	@(cd $@ && $(MAKE))

userdata:
	@(cd $@ && $(MAKE))

aws:	api userdata
	@(cd $@ && $(MAKE))

cloudwatt:	api userdata openstack
	@(cd $@ && $(MAKE))

flexibleengine:	api userdata openstack
	@(cd $@ && $(MAKE))

opentelekom:	api userdata flexibleengine
	@(cd $@ && $(MAKE))

openstack:	api userdata
	@(cd $@ && $(MAKE))

ovh:	api userdata openstack
	@(cd $@ && $(MAKE))

clean:
	@(for d in $(DIRECTORIES); do (cd $$d; $(MAKE) $@); done)
