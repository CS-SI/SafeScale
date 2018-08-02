GO?=go
EXEC:=perform

.PHONY: clean

all:	$(EXEC)

vet:
	@$(GO) vet
	@$(GO) vet ./cmds

$(EXEC): main.go cmds/*.go
	@$(GO) build -o $(EXEC)

clean:
	@$(RM) $(EXEC)

