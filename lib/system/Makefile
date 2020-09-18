GO?=go

.PHONY: clean generate nfs

all: nfs

vet:
	@$(GO) vet $(BUILD_TAGS) ./...

nfs:
	@(cd nfs && $(MAKE) all)

generate:
	@(cd nfs && $(MAKE) $(@))
	@($(GO) generate $(BUILD_TAGS) .)

clean:
	@(cd nfs && $(MAKE) $(@))
	@$(RM) rice-box.go || true
