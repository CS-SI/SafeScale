GO?=go
EXEC:=brokerd

.PHONY:	brokerd clean

all:	brokerd

vet:
	@$(GO) vet ./...

brokerd: main.go ../../daemon/services/*.go ../../daemon/commands/*.go ../../utils/*.go ../../broker.pb.go
	@$(GO) build -o $(EXEC)
	@$(GO) test -o brokerdcc -covermode count &> /dev/null

clean:
	@$(RM) $(EXEC) || true
