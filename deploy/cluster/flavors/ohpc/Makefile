GO?=go

.PHONY: generate clean

vet:
	@$(GO) vet ./...

clean:
	@($(RM) -f rice-box.go || true)
	@($(RM) ErrorCode/*_string.go || true)
