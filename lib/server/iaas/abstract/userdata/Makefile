GO?=go

.PHONY: clean generate vet

generate:
	@$(GO) generate

vet:
	@$(GO) vet $(BUILD_TAGS) ./...

clean:
	@($(RM) rice-box.go enums/*/enum_string.go || true)
