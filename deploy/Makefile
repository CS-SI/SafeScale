GO?=go

.PHONY: clean cluster install service cli vet

all:    cluster install cli #service

vet:
	@$(GO) vet ./...

cli:	cluster #service
	@(cd cli && $(MAKE))

cluster:
	@(cd cluster && $(MAKE))

service:
	@(cd service && $(MAKE))

clean:
	@(cd cli && $(MAKE) $(@))
	@(cd cluster && $(MAKE) $(@))
	#@(cd service && $(MAKE) $(@))

