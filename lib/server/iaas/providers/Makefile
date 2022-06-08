GO?=go

#.PHONY:	all clean generate vet
.PHONY:	clean vet

generate: clean
	@(mkdir -p ./mocks) || true

vet:
	@$(GO) vet ./...

clean:
	@$(RM) ./mocks/mock_*.go || true
