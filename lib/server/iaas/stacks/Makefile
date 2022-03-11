GO?=go

.PHONY:	clean vet

generate:
	@(mkdir -p mocks) || true
	@(mkdir -p api/mocks) || true

vet:
	@$(GO) vet $($(GO) list ./...)

clean:
	@$(RM) ./mocks/mock_*.go || true
