GO?=go
EXEC:=perform

all:	$(EXEC) cluster

.PHONY: cluster clean

cluster:
	@(cd cluster && $(MAKE))

$(EXEC): main.go cmd/*.go
	@$(GO) build -o $(EXEC)

clean:
	@$(RM) $(EXEC)
	@(cd cluster && $(MAKE) $@)

