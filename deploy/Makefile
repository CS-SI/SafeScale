GO?=go
EXEC:=deploy

.PHONY: clean cluster vet

all:    $(EXEC)

vet:
	@$(GO) vet
	@$(GO) vet ./cmds

$(EXEC): main.go cmds/*.go cluster
	@$(GO) build -o $(EXEC)

cluster:
	@(cd cluster && $(MAKE))

clean:
	@(cd cluster && $(MAKE) $(@))
	@$(RM) $(EXEC)

