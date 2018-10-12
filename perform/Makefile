GO?=go
EXEC:=perform
EXEC-COVER:=perform-cover

.PHONY: clean vet

default: all

vet:
	@$(GO) vet ./...

all: clean
	@$(GO) build -o $(EXEC)
	@$(GO) test -o $(EXEC-COVER) -covermode=count -coverpkg=github.com/CS-SI/SafeScale/... >/dev/null 2>&1

clean:
	@$(RM) $(EXEC) || true
	@$(RM) $(EXEC-COVER) || true

