GO?=go

.PHONY: all clean generate vet

VERSIONFILE := version.go
REV := `git rev-parse HEAD 2>/dev/null || echo ""`

all: generate

generate: clean gensrc
	@$(GO) generate -run rice .

gensrc:
	@$(RM) $(VERSIONFILE) || true
	@echo "package userdata" > $(VERSIONFILE)
	@echo "const (" >> $(VERSIONFILE)
	@echo "  REV = \"$(REV)\"" >> $(VERSIONFILE)
	@echo ")" >> $(VERSIONFILE)

vet:
	@$(GO) vet ./...

clean:
	@($(RM) rice-box.go || true)
