GO?=go
DIRECTORIES_ = $(sort $(dir $(wildcard */)))
DIRECTORIES = $(filter-out tests/ metadata/, $(DIRECTORIES_))

.PHONY:	api aws cloudwatt flexibleengine openstack opentelekom ovh userdata

all:	api aws cloudwatt flexibleengine openstack opentelekom ovh userdata

vet:
	@$(GO) vet ./...

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
	@echo "Cleaning"
