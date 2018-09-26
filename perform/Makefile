GO?=go
EXEC:=perform

.PHONY: clean

all:	$(EXEC)

vet:
	@$(GO) vet ./...

$(EXEC): main.go cmds/*.go
	@$(GO) build -o $(EXEC)

clean:
	@$(RM) $(EXEC)

