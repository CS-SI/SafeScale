GO?=go
EXEC:=scanner

default: all

all: clean
	@$(GO) build -o $(EXEC)

vet:
	@$(GO) vet ./...

.PHONY: clean vet

clean:
	@($(RM) scanner || true)

