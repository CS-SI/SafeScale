GO?=go

.PHONY: generate clean mrproper

vet:
	@$(GO) vet
	@$(GO) vet ./enums/ErrorCode

clean:
	@($(RM) -f rice-box.go)

mrproper: clean
