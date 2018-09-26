GO?=go

.PHONY: generate clean mrproper

vet:
	@$(GO) vet ./...

clean:
	@($(RM) -f rice-box.go)
	@($(RM) ErrorCode/*_string.go)

mrproper: clean
