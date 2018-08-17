GO?=go

.PHONY: clean api vet

all:    api

vet:
	@$(GO) vet
	@$(GO) vet ./cmds

api:	
	@(cd api && $(MAKE))

clean:
	@(cd api && $(MAKE) $(@))

