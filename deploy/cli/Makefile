GO?=go
EXEC:=deploy
EXEC-COVER:=deploy-cover

BUILD_DATE := `date +%Y-%m-%d\ %H:%M`
VERSIONFILE := version.go

.PHONY: clean vet

DIRECTORIES := $(sort $(dir $(wildcard */)))

default: all

vet:
	@$(GO) vet ./...

all: clean gensrc
	@$(GO) build -o $(EXEC)
	@$(GO) test -o $(EXEC-COVER) -covermode=count -coverpkg=github.com/CS-SI/SafeScale/... >/dev/null 2>&1

clean:
	@$(RM) $(EXEC-COVER) || true
	@$(RM) $(EXEC) || true
	@(cd enums && $(MAKE) $@)

gensrc:
	@$(RM) $(VERSIONFILE) || true
	@echo "package main" > $(VERSIONFILE)
	@echo "const (" >> $(VERSIONFILE)
	@echo "  VERSION = \"0.1\"" >> $(VERSIONFILE)
	@echo "  BUILD_DATE = \"$(BUILD_DATE)\"" >> $(VERSIONFILE)
	@echo ")" >> $(VERSIONFILE)