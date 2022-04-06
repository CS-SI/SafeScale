GO?=go

.PHONY:	vet

vet:
	@$(GO) vet ./...

generate:
	@(mkdir -p mocks) || true
	@$(GO) generate -run minimock . >/dev/null || true

clean:
	@($RM) -f mocks/*.go || true
