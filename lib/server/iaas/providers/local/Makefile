GO?=go

.PHONY:	clean generate test vet

generate:
	@$(GO) generate -tags libvirt ./...

vet:
	@$(GO) vet ./...

test:
	@$(GO) test

clean:
	@($(RM) rice-box.go || true)
