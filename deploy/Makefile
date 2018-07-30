GO?=go
EXEC:=deploy

all:    $(EXEC)  vet

.PHONY: clean vet

vet:
	@$(GO) vet
	@$(GO) vet ./cmds

$(EXEC): main.go cmds/*.go
	@$(GO) build -o $(EXEC)

clean:
	@$(RM) $(EXEC)

