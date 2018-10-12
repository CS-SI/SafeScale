GO?=go
EXEC:=broker
EXEC-COVER:=broker-cover

.PHONY:	vet clean

default: all

vet:
	@$(GO) vet ./...

all: clean
	@$(GO) build -o $(EXEC)
	@$(GO) test -o $(EXEC-COVER) -covermode=count -coverpkg=github.com/CS-SI/SafeScale/... >/dev/null 2>&1

clean:
	@$(RM) $(EXEC-COVER) || true
	@$(RM) $(EXEC) || true
