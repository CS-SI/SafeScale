GO?=go

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

.PHONY: clean vet

DIRECTORIES := $(sort $(dir $(wildcard */)))

default: all

vet:
	@$(GO) vet ./...

all: clean gensrc
	@$(GO) build -race -o $(EXEC) $(BUILD_TAGS)
	@$(GO) test -o $(EXEC-COVER) -covermode=count -coverpkg=github.com/CS-SI/SafeScale/... >/dev/null 2>&1

clean:
	@$(RM) $(EXEC) || true
	@$(RM) $(EXEC-COVER) || true
	@(for d in $(DIRECTORIES); do (cd $$d; $(RM) *_string.go || true); done)

gensrc:
	@$(RM) $(VERSIONFILE) || true
	@echo "package main" > $(VERSIONFILE)
	@echo "const (" >> $(VERSIONFILE)
	@echo "  VERSION = \"19.03.0\"" >> $(VERSIONFILE)
	@echo "  BUILD_DATE = \"$(BUILD_DATE)\"" >> $(VERSIONFILE)
	@echo "  REV = \"$(REV)\"" >> $(VERSIONFILE)
	@echo ")" >> $(VERSIONFILE)