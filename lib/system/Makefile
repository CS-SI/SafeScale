GO?=go

.PHONY: clean generate nfs

all: nfs

vet:
	@$(GO) vet ./...

nfs:
	@(cd nfs && $(MAKE) all)

generate:
	@(cd nfs && $(MAKE) $(@))

clean:
	@(cd firewall && $(MAKE) $(@)
	@(cd nfs && $(MAKE) $(@)
	@$(RM) rice-box.go || true
