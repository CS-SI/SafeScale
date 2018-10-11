GO?=go
EXEC:=brokerd

.PHONY:	brokerd clean

all:	brokerd

vet:
	@$(GO) vet ./...

brokerd: main.go ../../daemon/services/*.go ../../daemon/commands/*.go ../../utils/*.go ../../broker.pb.go
	@$(RM) brokerd || true
	@$(GO) build -o $(EXEC)
	@$(RM) brokerd-cover || true
	@$(GO) test -o brokerd-cover -covermode=count -coverpkg=github.com/CS-SI/SafeScale/... >/dev/null 2>&1

clean:
	@$(RM) $(EXEC) || true
