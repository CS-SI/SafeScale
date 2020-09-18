GO?=go

.PHONY:	clean generate test vet

generate:
	@$(GO) generate $(BUILD_TAGS) ./...

vet:
	@$(GO) vet $(BUILD_TAGS) ./...

test:
	@$(GO) test

clean:
	@($(RM) rice-box.go || true)

