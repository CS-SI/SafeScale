GO?=go

.PHONY: clean generate nfs

all: nfs

vet:
	@$(GO) vet ./...

nfs:
	@(cd nfs && $(MAKE) all)

generate:
	@(cd nfs && $(MAKE) $(@))
	@(go generate .)

clean:
	@(cd nfs && $(MAKE) $(@))
	@$(RM) rice-box.go || true
