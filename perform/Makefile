GO?=go
EXEC:=perform

all:	$(EXEC) cluster vet

.PHONY: cluster clean

vet:
	@$(GO) vet
	@$(GO) vet ./utils
	@$(GO) vet ./cmd

cluster:
	@(cd cluster && $(MAKE))

$(EXEC): cluster main.go cmd/*.go
	@$(GO) build -o $(EXEC)

clean:
	@$(RM) $(EXEC)
	@(cd cluster && $(MAKE) $@)

