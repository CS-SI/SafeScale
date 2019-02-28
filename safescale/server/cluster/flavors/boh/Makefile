GO?=go

.PHONY: generate clean

vet:
	@$(GO) vet ./...

clean:
	@(cd enums && $(MAKE) $@)
	@($(RM) -f rice-box.go || true)
	
