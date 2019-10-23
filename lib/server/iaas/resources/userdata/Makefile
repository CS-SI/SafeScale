GO?=go

.PHONY: clean generate vet

VERSIONFILE := version.go
REV := `git rev-parse HEAD 2>/dev/null || echo ""`

all: generate

gensrc:
	@$(RM) $(VERSIONFILE) || true
	@echo "package userdata" > $(VERSIONFILE)
	@echo "const (" >> $(VERSIONFILE)
	@echo "  REV = \"$(REV)\"" >> $(VERSIONFILE)
	@echo ")" >> $(VERSIONFILE)

generate: gensrc
	@$(GO) generate

vet:
	@$(GO) vet ./...

clean:
	@($(RM) rice-box.go enums/*/enum_string.go || true)
