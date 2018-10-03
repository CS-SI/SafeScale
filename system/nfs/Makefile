GO?=go

.PHONY: nfs clean

vet:
	@$(GO) vet ./...

generate:
	@(cd SecurityFlavor && $(GO) generate)
	@$(GO) generate

clean:
	@$(RM) rice-box.go SecurityFlavor/enum_string.go
