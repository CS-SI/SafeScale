GO?=go

.PHONY:	clean vet

vet:
	@$(GO) vet $(BUILD_TAGS) ./...

clean:
	@$(RM) ./mocks/*.go || true
