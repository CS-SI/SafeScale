GO?=go
EXEC:=brokerd

.PHONY:	brokerd clean

all:	brokerd

vet:
	@$(GO) vet ./...

brokerd: main.go ../../daemon/services/*.go ../../daemon/commands/*.go ../../utils/*.go ../../broker.pb.go
	@$(GO) build -o $(EXEC)

clean:
	@$(RM) $(EXEC)
