GO?=go

.PHONY: generate clean

vet:
	@$(GO) vet ./...

generate:
	@$(GO) generate ./...

clean:
	@(cd enums && $(MAKE) $@)
	@($(RM) -f rice-box.go || true)
