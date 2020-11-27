GO?=go

.PHONY:	clean vet

vet:
	@$(GO) vet $($(GO) list ./... | grep -v libvirt | grep -v vclouddirector)

clean:
	@$(RM) ./mocks/*.go || true
