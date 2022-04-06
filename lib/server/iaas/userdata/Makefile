GO?=go

.PHONY: all clean generate vet

VERSIONFILE := version.go
REV := `git rev-parse HEAD 2>/dev/null || echo ""`

all: generate

generate: clean gensrc
	@:

gensrc:
	@$(RM) $(VERSIONFILE) || true
	@echo "package userdata" > $(VERSIONFILE)
	@echo "const (" >> $(VERSIONFILE)
	@echo "  REV = \"$(REV)\"" >> $(VERSIONFILE)
	@echo "  Tags = \"$(BUILD_TAGS)\"" >> $(VERSIONFILE)
	@echo ")" >> $(VERSIONFILE)
	@gofmt $(VERSIONFILE) > /dev/null 2>&1

vet:
	@$(GO) vet ./...

clean:
	@:
