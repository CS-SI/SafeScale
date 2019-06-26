include ../../common.mk

ifeq ($(OS),Windows_NT)
	EXEC:=scanner.exe
else
	EXEC:=scanner
endif

BUILD_DATE := `date +%Y/%m/%d-%H:%M`
VERSIONFILE := version.go
REV := `git rev-parse HEAD 2>/dev/null || echo ""`

default: all

all: clean gensrc
	@$(GO) build -race -o $(EXEC) $(BUILD_TAGS)

vet:
	@$(GO) vet ./...

.PHONY: clean vet

clean:
	@($(RM) $(EXEC) || true)

gensrc:
	@($(RM) -f $(VERSIONFILE) || true)
	@echo "package main" > $(VERSIONFILE)
	@echo "const (" >> $(VERSIONFILE)
	@echo "  VERSION = \"$(VERSION)\"" >> $(VERSIONFILE)
	@echo "  BUILD_DATE = \"$(BUILD_DATE)\"" >> $(VERSIONFILE)
	@echo "  REV = \"$(REV)\"" >> $(VERSIONFILE)
	@echo ")" >> $(VERSIONFILE)
