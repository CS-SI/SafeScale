GO?=go

.PHONY: clean generate cluster install service cli vet

all:    generate cluster install cli #service

generate:
	@$(GO) generate ./...

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
	@$(RM) ./mocks/*.go || true

