GO?=go
EXEC:=brokerd
EXEC-COVER:=brokerd-cover

.PHONY:	vet clean

default: all

vet:
	@$(GO) vet ./...

all: clean
	@$(GO) build -o $(EXEC)
	@$(GO) test -o brokerd-cover -covermode=count -coverpkg=github.com/CS-SI/SafeScale/... >/dev/null 2>&1

clean:
	@$(RM) $(EXEC-COVER) || true
	@$(RM) $(EXEC) || true
