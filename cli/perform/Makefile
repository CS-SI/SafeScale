include ../../common.mk

ifeq ($(OS),Windows_NT)
	EXEC:=perform.exe
	EXEC-COVER:=perform-cover.exe
else
	EXEC:=perform
	EXEC-COVER:=perform-cover
endif

BUILD_DATE := `date +%Y/%m/%d-%H:%M`
VERSIONFILE := version.go
REV := `git rev-parse HEAD 2>/dev/null || echo ""`

.PHONY: clean generate vet

default: all

vet:
	@$(GO) vet ./...

all: clean gensrc
	@$(GO) build -race -o $(EXEC) $(BUILD_TAGS)
	@$(GO) test -o $(EXEC-COVER) -covermode=count -coverpkg=github.com/CS-SI/SafeScale/... >/dev/null 2>&1

clean:
	@$(RM) $(EXEC) || true
	@$(RM) $(EXEC-COVER) || true
	@(cd enums && $(MAKE) $(@))

generate: gensrc
	@(cd enums && $(MAKE) $(@))

gensrc:
	@$(RM) $(VERSIONFILE) || true
	@echo "package main" > $(VERSIONFILE)
	@echo "// Build constants" >> $(VERSIONFILE)
	@echo "const (" >> $(VERSIONFILE)
	@echo "    Version   = \"$(VERSION)\"" >> $(VERSIONFILE)
	@echo "    BuildDate = \"$(BUILD_DATE)\"" >> $(VERSIONFILE)
	@echo "    Revision  = \"$(REV)\"" >> $(VERSIONFILE)
	@echo ")" >> $(VERSIONFILE)
