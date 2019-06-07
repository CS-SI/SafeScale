GO?=go

.PHONY:	generate clean test vet

generate:
	@$(GO) generate ./...
	
vet:
	@$(GO) vet ./...

test:
	$(GO) test

clean:
	@($(RM) rice-box.go || true)
