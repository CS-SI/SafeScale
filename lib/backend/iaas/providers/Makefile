GO?=go

#.PHONY:	all clean generate vet
.PHONY:	clean vet

generate: clean
	@(mkdir -p ./mocks) || true

vet:
	@(mkdir -p ./mocks) || true
	@$(GO) vet ./...

clean:
	@$(RM) ./mocks/mock_*.go || true
