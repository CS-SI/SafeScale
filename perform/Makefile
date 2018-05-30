GO?=go
EXEC:=perform

all:	$(EXEC) cluster

.PHONY: cluster utils clean

cluster:
	@(cd cluster && $(MAKE))

$(EXEC): main.go cmd/*.go utils/*.go cluster
	@$(GO) build -o $(EXEC)

utils:
	@(cd cmd && $(MAKE))

clean:
	@$(RM) $(EXEC)
	@(cd cluster && $(MAKE) $@)

