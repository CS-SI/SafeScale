GO?=go

.PHONY: clean generate nfs

VERSIONFILE := version.go
REV := `git rev-parse HEAD 2>/dev/null || echo ""`

all: nfs generate

vet:
	@$(GO) vet ./...

test:
	@(cd scripts && $(MAKE) $(@))

bashtest:
	@(cd scripts && $(MAKE) $(@))

nfs:
	@(cd nfs && $(MAKE) all)

generate: clean gensrc
	@(cd nfs && $(MAKE) $(@))
	@$(GO) generate . > /dev/null 2>&1
	@$(GO) fmt $(VERSIONFILE) > /dev/null 2>&1

gensrc:
	@$(RM) $(VERSIONFILE) || true
	@echo "package system" > $(VERSIONFILE)
	@echo "const (" >> $(VERSIONFILE)
	@echo "  REV = \"$(REV)\"" >> $(VERSIONFILE)
	@echo "  Tags = \"$(BUILD_TAGS)\"" >> $(VERSIONFILE)
	@echo ")" >> $(VERSIONFILE)

clean:
	@(cd nfs && $(MAKE) $(@))
	@$(RM) rice-box.go || true
