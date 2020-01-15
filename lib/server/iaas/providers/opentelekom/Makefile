GO?=go

.PHONY:	clean generate test vet

generate: clean
	@$(GO) generate ./...

vet:
	@$(GO) vet ./...

test:
	@$(GO) test

clean:
	@($(RM) rice-box.go || true)

