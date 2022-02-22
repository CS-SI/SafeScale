GO?=go

.PHONY: clean generate vet

all: generate

vet:
	@$(GO) vet ./...

generate:
	@(cd enums && $(MAKE) $(@))

clean:
	@$(RM) enums/*/enum_string.go || true
