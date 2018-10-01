GO?=go

.PHONY:	generate enums api aws cloudwatt flexibleengine openstack opentelekom ovh userdata

all:	generate enums api aws cloudwatt flexibleengine openstack opentelekom ovh userdata

generate:
	@$(GO) generate ./...

vet:
	@$(GO) vet ./...

api:
	@(cd $@ && $(MAKE))

enums:
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
