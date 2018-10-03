GO?=go
EXEC:=deploy

.PHONY: clean vet

all:    $(EXEC)

vet:
	@$(GO) vet ./...

$(EXEC): main.go cmds/*.go
	@$(GO) build -o $(EXEC)

clean:
	@$(RM) $(EXEC) || true
