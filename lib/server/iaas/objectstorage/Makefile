GO?=go

#.PHONY:	all clean generate vet
.PHONY:	clean vet

generate: clean
	@(mkdir -p ./mocks) || true
	@$(GO) generate -run minimock . >/dev/null 2>&1 || true

vet:
	@$(GO) vet ./...

clean:
	@$(RM) ./mocks/mock_*.go || true
