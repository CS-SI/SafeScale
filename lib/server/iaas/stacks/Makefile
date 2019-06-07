GO?=go

.PHONY:	clean vet

vet:
	@$(GO) vet ./...

clean:
	@$(RM) ./mocks/*.go || true
