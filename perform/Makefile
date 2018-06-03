GO?=go
EXEC:=perform

all:	$(EXEC) cluster vet

.PHONY: cluster utils clean

vet:
	@$(GO) vet
	@$(GO) vet ./utils
	@$(GO) vet ./cmd

cluster:
	@(cd cluster && $(MAKE))

$(EXEC): main.go cmd/*.go utils/*.go cluster
	@$(GO) build -o $(EXEC)

utils:
	@(cd cmd && $(MAKE))

clean:
	@$(RM) $(EXEC)
	@(cd cluster && $(MAKE) $@)

