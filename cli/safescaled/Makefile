include ../../common.mk

ifeq ($(OS),Windows_NT)
	EXEC:=safescaled.exe
	EXEC-COVER:=safescaled-cover.exe
else
	EXEC:=safescaled
	EXEC-COVER:=safescaled-cover
endif

BUILD_DATE := `date +%Y/%m/%d-%H:%M`
VERSIONFILE := version.go
REV := `git rev-parse HEAD 2>/dev/null || echo ""`

.PHONY:	vet clean

default: all

vet:
	@$(GO) vet ./...

all: clean gensrc
	@$(GO) build -race -o $(EXEC) $(BUILD_TAGS)
	@$(GO) test -o $(EXEC-COVER) $(BUILD_TAGS) -covermode=count -coverpkg=github.com/CS-SI/SafeScale/... >/dev/null 2>&1

clean:
	@$(RM) $(EXEC-COVER) || true
	@$(RM) $(EXEC) || true

generate: gensrc

gensrc:
	@$(RM) $(VERSIONFILE) || true
	@echo "package main" > $(VERSIONFILE)
	@echo "// Build constants" >> $(VERSIONFILE)
	@echo "const (" >> $(VERSIONFILE)
	@echo "    Version = \"$(VERSION)\"" >> $(VERSIONFILE)
	@echo "    BuildDate = \"$(BUILD_DATE)\"" >> $(VERSIONFILE)
	@echo "    Revision = \"$(REV)\"" >> $(VERSIONFILE)
	@echo ")" >> $(VERSIONFILE)