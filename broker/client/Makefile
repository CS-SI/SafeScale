GO?=go
EXEC:=broker

.PHONY:	broker clean

all:	broker

vet:
	@$(GO) vet ./...

broker:
	@$(GO) build -race -o $(EXEC)

clean:
	@$(RM) $(EXEC) || true
