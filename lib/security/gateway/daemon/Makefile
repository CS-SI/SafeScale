GO?=go
EXEC:=safe-securityd

.PHONY:	safe-securityd clean

all: safe-securityd

vet:
	@$(GO) vet $(BUILD_TAGS) ./...

safe-securityd:	proxy.go
	@CGO_ENABLED=0 $(GO) build $(RACE_CHECK) -o $(EXEC)

clean:
	@$(RM) $(EXEC) || true
