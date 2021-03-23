GO?=go

.PHONY:	generate test vet

generate:
	@$(GO) generate -tags libvirt ./...

vet:
	@$(GO) vet ./...

test:
	@$(GO) test $(RACE_CHECK_TEST) -v ./...
