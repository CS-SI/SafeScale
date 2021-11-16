GO?=go

.PHONY:	test vet

vet:
	@$(GO) vet ./...

test:
	@$(GO) test $(RACE_CHECK_TEST) $(GO_TEST_TAGS) -v ./...
