GO?=go

.PHONY:	vet

vet:
	@$(GO) vet ./...

generate:
	@(mkdir -p ../mocks) || true

clean:
	@$(RM) ./mocks/mock_*.go || true
