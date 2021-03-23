
.PHONY:	test vet

vet:
	@$(GO) vet ./...

test:
	@$(GO) test $(RACE_CHECK_TEST) -v ./...

