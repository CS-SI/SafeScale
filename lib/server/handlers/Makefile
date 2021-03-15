GO?=go

.PHONY:	vet

vet:
	@$(GO) vet ./...

generate:
	@(mkdir -p ../mocks) || true
	@$(GO) generate -run minimock .

clean: ;
