GO?=go
EXEC:=brokerd

.PHONY:	brokerd clean

all:	brokerd

vet:
	@$(GO) vet ./...

brokerd: main.go ../../daemon/services/*.go ../../daemon/commands/*.go ../../utils/*.go ../../broker.pb.go
	@$(RM) brokerd || true
	@$(GO) build -o $(EXEC)
	@$(RM) brokerdcc || true
	@$(GO) test -o brokerdcc -covermode=count -coverpkg=github.com/CS-SI/SafeScale/... >/dev/null 2>&1

clean:
	@$(RM) $(EXEC) || true
