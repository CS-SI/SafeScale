GO?=go
EXEC:=safe-security

.PHONY:	safe-security clean

all: safe-security

vet:
	@$(GO) vet $(BUILD_TAGS) ./...

safe-security:	main.go
	@$(GO) build $(RACE_CHECK) -o $(EXEC)

clean:
	@$(RM) $(EXEC) || true
