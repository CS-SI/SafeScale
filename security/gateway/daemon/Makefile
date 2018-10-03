GO?=go
EXEC:=safe-securityd

.PHONY:	safe-securityd clean

all: safe-securityd

vet:
	@$(GO) vet ./...

safe-securityd:	proxy.go
	@$(GO) build -o $(EXEC)

clean:
	@$(RM) $(EXEC) || true
