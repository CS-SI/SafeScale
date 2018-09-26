GO?=go
DIRECTORIES_ = $(sort $(dir $(wildcard */)))
DIRECTORIES = $(filter-out api/ tests/ metadata/ filters/, $(DIRECTORIES_))

.PHONY:	enums filters cloudwatt flexibleengine openstack opentelekom ovh userdata clean #aws

all:	enums filters cloudwatt flexibleengine openstack opentelekom ovh userdata #aws

vet:
	@$(GO) vet
	@$(GO) vet ./tests

enums:
	@(cd $@ && $(MAKE))

filters:
	@(cd $@ && $(MAKE))

userdata:
	@(cd $@ && $(MAKE))

aws:	api enums filters userdata
	@(cd $@ && $(MAKE))

cloudwatt:	api enums filters userdata openstack
	@(cd $@ && $(MAKE))

flexibleengine:	api enums filters userdata openstack
	@(cd $@ && $(MAKE))

opentelekom:	api enums filters userdata flexibleengine
	@(cd $@ && $(MAKE))

openstack:	api enums filters userdata
	@(cd $@ && $(MAKE))

ovh:	api enums filters userdata openstack
	@(cd $@ && $(MAKE))

clean:
	@(for d in $(DIRECTORIES); do (cd $$d; $(MAKE) $@); done)
