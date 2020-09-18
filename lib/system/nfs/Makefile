GO?=go

.PHONY: clean generate vet

all: generate

vet:
	@$(GO) vet $(BUILD_TAGS) ./...

generate:
	@(cd enums && $(MAKE) $(@))
	@$(GO) generate -run rice

clean:
	@$(RM) rice-box.go enums/*/enum_string.go || true
