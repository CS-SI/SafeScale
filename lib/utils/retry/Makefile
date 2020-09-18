GO?=go

.PHONY: clean generate vet

all:    generate

generate:
	@(cd enums && $(MAKE) $(@))

vet:
	@$(GO) vet $(BUILD_TAGS) ./...

clean:
	@$(RM) ./enums/*/enum_string.go || true
