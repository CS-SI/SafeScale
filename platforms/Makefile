GO?=go
DIRECTORIES_ = $(sort $(dir $(wildcard */)))
DIRECTORIES = $(filter-out tests/ metadata/, $(DIRECTORIES_))

.PHONY:	api enums aws huaweicloud openstack userdata filters clean

all:	api enums aws huaweicloud openstack userdata

vet:
	@$(GO) vet
	@$(GO) vet ./tests

api:
	@(cd $@ && $(MAKE))

filters:
	@(cd $@ && $(MAKE))

userdata:
	@(cd $@ && $(MAKE))

aws:	api userdata
	@(cd $@ && $(MAKE))

enums:	
	@(cd $@ && $(MAKE))

huaweicloud:	api userdata openstack
	@(cd $@ && $(MAKE))

openstack:	api userdata
	@(cd $@ && $(MAKE))

clean:
	@(for d in $(DIRECTORIES); do (cd $$d; $(MAKE) $@); done)
