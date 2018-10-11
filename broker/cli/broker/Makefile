GO?=go
EXEC:=broker

.PHONY:	broker clean

all:	broker

vet:
	@$(GO) vet ./...

broker:	main.go cmd/*.go ../../utils/*.go ../../broker.pb.go
	@$(RM) broker || true
	@$(GO) build -o $(EXEC)
	@$(RM) brokercc || true
	@$(GO) test -o brokercc -covermode=count -coverpkg=github.com/CS-SI/SafeScale/... >/dev/null 2>&1

clean:
	@$(RM) $(EXEC) || true
