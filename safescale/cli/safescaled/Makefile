GO?=go

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

gensrc:
	@$(RM) $(VERSIONFILE) || true
	@echo "package main" > $(VERSIONFILE)
	@echo "const (" >> $(VERSIONFILE)
	@echo "  VERSION = \"19.03.3\"" >> $(VERSIONFILE)
	@echo "  BUILD_DATE = \"$(BUILD_DATE)\"" >> $(VERSIONFILE)
	@echo "  REV = \"$(REV)\"" >> $(VERSIONFILE)
	@echo ")" >> $(VERSIONFILE)
