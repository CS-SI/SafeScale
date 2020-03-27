GO?=go
EXEC:=safe-security

.PHONY:	safe-security clean

all: safe-security

vet:
	@$(GO) vet ./...

safe-security:	main.go
	@$(GO) build $(RACE_CHECK) -o $(EXEC)

clean:
	@$(RM) $(EXEC) || true
