GO?=go

.PHONY: clean vet

all:    ErrorCode

vet:
	@$(GO) vet
	@$(GO) vet ./cmds

ErrorCode: ErrorCode/enum.go
	@$(GO) generate

clean:
	@$(RM) ErrorCode/enum_string.go
