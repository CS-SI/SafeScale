GO?=go

.PHONY:	clean vet

vet:
	@$(GO) vet ./...

generate: clean
	@$(GO) generate ./...

clean:
	@$(RM) rice-box.go || true

