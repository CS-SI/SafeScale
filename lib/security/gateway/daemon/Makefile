GO?=go
EXEC:=safe-securityd

.PHONY:	safe-securityd clean generate

all: safe-securityd

vet:
	@$(GO) vet ./...

safe-securityd: main.go
	@$(GO) build -race -o $(EXEC)

clean:
	@$(RM) $(EXEC) || true
