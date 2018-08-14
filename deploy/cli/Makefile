GO?=go
EXEC:=deploy

.PHONY: clean vet

all:    $(EXEC)

vet:
	@$(GO) vet
	@$(GO) vet ./cmds

$(EXEC): main.go cmds/*.go
	@$(GO) build -o $(EXEC)

clean:
	@$(RM) $(EXEC)
