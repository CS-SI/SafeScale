GO?=go

all: generate enums vet

.PHONY: generate enums clean mrproper

vet:
	@$(GO) vet
	@$(GO) vet ./ErrorCode

enums: ErrorCode/enum_string.go

ErrorCode/enum_string.go: ErrorCode/enum.go
	@(cd ErrorCode && $(GO) generate)

generate: dcos.go scripts/*.sh
	@echo "Generating dependencies..."
	@$(GO) generate

clean:
	@($(RM) -f rice-box.go)

mrproper: clean

