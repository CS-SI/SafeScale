GO?=go
EXEC:=broker

.PHONY:	broker clean

all:	broker vet

vet:
	@$(GO) vet
	@$(GO) vet ./cmd

broker:	main.go cmd/*.go ../utils/*.go ../broker.pb.go
	@$(GO) build -o $(EXEC)

clean:
	@$(RM) $(EXEC)
