GO?=go

.PHONY: generate enums clean mrproper

all: generate enums

vet:
	@$(GO) vet
	@$(GO) vet ./ErrorCode

enums: ErrorCode/enum_string.go

ErrorCode/enum_string.go: ErrorCode/enum.go
	@(cd ErrorCode && $(GO) generate)

clean:
	@($(RM) -f rice-box.go)

mrproper: clean
