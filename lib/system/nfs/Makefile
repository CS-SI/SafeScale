GO?=go

.PHONY: clean generate vet

all: generate

vet:
	@$(GO) vet ./...

generate: clean
	@(cd enums && $(MAKE) $(@))
	@$(GO) generate -run rice

clean:
	@$(RM) rice-box.go enums/*/enum_string.go || true
