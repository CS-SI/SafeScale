GO?=go

.PHONY: clean cluster install service cli vet

all:    cluster install cli #service

vet:
	@$(GO) vet
	@$(GO) vet ./cmds

cli:	cluster install #service
	@(cd cli && $(MAKE))

cluster:
	@(cd cluster && $(MAKE))

install:
	@(cd install && $(MAKE))

service:
	@(cd service && $(MAKE))

clean:
	@(cd cli && $(MAKE) $(@))
	@(cd cluster && $(MAKE) $(@))
	@(cd install && $(MAKE) $(@))
	#@(cd service && $(MAKE) $(@))

