GO?=go
EXEC:=scanner

BUILD_DATE := `date +%Y-%m-%d\ %H:%M`
VERSIONFILE := version.go

default: all

all: clean gensrc
	@$(GO) build -o $(EXEC)

vet:
	@$(GO) vet ./...

.PHONY: clean vet

clean:
	@($(RM) $(EXEC) || true)

gensrc:
	@($(RM) -f $(VERSIONFILE) || true)
	@echo "package main" > $(VERSIONFILE)
	@echo "const (" >> $(VERSIONFILE)
	@echo "  VERSION = \"0.1\"" >> $(VERSIONFILE)
	@echo "  BUILD_DATE = \"$(BUILD_DATE)\"" >> $(VERSIONFILE)
	@echo ")" >> $(VERSIONFILE)
