GO?=go

.PHONY: clean vet

all:

vet:
	@$(GO) vet
	@$(GO) vet ./cmds

cli:	cluster install service
	@(cd cli && $(MAKE))

clean:
	@$(RM) $(EXEC)

