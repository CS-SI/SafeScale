GO?=go
EXEC:=broker

.PHONY:	broker clean

all:	broker

vet:
	@$(GO) vet ./...

broker:	main.go cmd/*.go ../../utils/*.go ../../broker.pb.go
	@$(GO) build -o $(EXEC)
	@$(GO) test -o brokercc -covermode count &> /dev/null

clean:
	@$(RM) $(EXEC) || true
