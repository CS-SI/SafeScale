GO?=go

.PHONY: clean cluster install service cli vet

all:    cluster install service cli

vet:
	@$(GO) vet
	@$(GO) vet ./cmds

cli:	cluster install service
	@(cd cli && $(MAKE))

cluster:
	@(cd cluster && $(MAKE))

install:
	@(cd cluster && $(MAKE))

service:
	@(cd cluster && $(MAKE))

clean:
	@(cd cluster && $(MAKE) $(@))
	@$(RM) $(EXEC)

