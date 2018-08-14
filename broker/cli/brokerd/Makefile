GO?=go
EXEC:=brokerd

.PHONY:	brokerd clean

all:	brokerd

vet:
	@$(GO) vet
	@$(GO) vet ./commands

brokerd: main.go commands/*.go ../../daemon/services/*.go ../../utils/*.go ../../broker.pb.go
	@$(GO) build -o $(EXEC)

clean:
	@$(RM) $(EXEC)
