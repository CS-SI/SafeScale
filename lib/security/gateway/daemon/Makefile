GO?=go
EXEC:=safe-securityd

.PHONY:	safe-securityd clean

all: safe-securityd

vet:
	@$(GO) vet $(BUILD_TAGS) ./...

safe-securityd:	proxy.go
	@$(GO) build $(RACE_CHECK) -o $(EXEC)

clean:
	@$(RM) $(EXEC) || true
