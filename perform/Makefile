GO?=go
EXEC:=perform

all:	$(EXEC) cluster

.PHONY: cluster utils clean

cluster:
	@(cd cluster && $(MAKE))

$(EXEC): main.go cmd/*.go utils/*.go
	@$(GO) build -o $(EXEC)

utils:
	@(cd command && $(MAKE))

clean:
	@$(RM) $(EXEC)
	@(cd cluster && $(MAKE) $@)
	@(cd command && $(MAKE) $@)

