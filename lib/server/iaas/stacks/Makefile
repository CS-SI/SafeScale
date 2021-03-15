GO?=go

.PHONY:	clean vet

generate:
	@(mkdir -p mocks) || true
	@(mkdir -p api/mocks) || true

vet:
	@$(GO) vet $($(GO) list ./... | grep -v libvirt | grep -v vclouddirector)

clean:
	@$(RM) ./mocks/*.go || true
