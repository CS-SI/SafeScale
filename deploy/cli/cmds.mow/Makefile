GO?=go

all:    ErrorCode vet

.PHONY: clean vet

vet:
	@$(GO) vet
	@$(GO) vet ./cmds

ErrorCode: ErrorCode/enum.go
	@$(GO) generate

clean:
	@$(RM) ErrorCode/enum_string.go
