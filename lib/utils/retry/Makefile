GO?=go

.PHONY: clean generate vet

all: generate

generate:
	@$(GO) generate ./...
	@(cd enums && $(MAKE) $(@))

vet:
	@$(GO) vet ./...

clean:
	@$(RM) ./enums/*/enum_string.go || true
