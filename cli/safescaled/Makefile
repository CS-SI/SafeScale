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
ifeq ($(BUILD_TAGS),)
	@$(GO) build $(RACE_CHECK) -o $(EXEC)
else
	@$(GO) build $(RACE_CHECK) -o $(EXEC) -tags $(BUILD_TAGS)
endif

allcover: clean gensrc
ifeq ($(BUILD_TAGS),)
	@$(GO) build $(RACE_CHECK) -o $(EXEC)
	@$(GO) test -o $(EXEC-COVER) -covermode=count -coverpkg=github.com/CS-SI/SafeScale/... >/dev/null 2>&1
else
	@$(GO) build $(RACE_CHECK) -o $(EXEC) -tags $(BUILD_TAGS)
	@$(GO) test -o $(EXEC-COVER) -tags $(BUILD_TAGS) -covermode=count -coverpkg=github.com/CS-SI/SafeScale/... >/dev/null 2>&1
endif

clean:
	@$(RM) $(EXEC-COVER) || true
	@$(RM) $(EXEC) || true

generate: gensrc
	@$(GO) fmt $(VERSIONFILE) > /dev/null 2>&1

gensrc:
	@$(RM) $(VERSIONFILE) || true
	@echo "package main" > $(VERSIONFILE)
	@echo "// Build constants" >> $(VERSIONFILE)
	@echo "const (" >> $(VERSIONFILE)
	@echo "    Version = \"$(VERSION)\"" >> $(VERSIONFILE)
	@echo "    BuildDate = \"$(BUILD_DATE)\"" >> $(VERSIONFILE)
	@echo "    Revision = \"$(REV)\"" >> $(VERSIONFILE)
	@echo "    Tags = \"$(BUILD_TAGS)\"" >> $(VERSIONFILE)
	@echo ")" >> $(VERSIONFILE)
