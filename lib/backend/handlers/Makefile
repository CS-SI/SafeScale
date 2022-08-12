GO?=go

.PHONY:	vet

vet:
	@$(GO) vet ./...

generate:
	@(mkdir -p ../mocks) || true
	@$(GO) generate -run minimock ./... > /dev/null 2>&1

clean:
	@$(RM) ./mocks/mock_*.go || true
