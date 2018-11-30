GO?=go
EXEC:=brokerd

.PHONY:	brokerd handlers clean

all:	brokerd 

vet:
	@$(GO) vet ./...

brokerd: handlers main.go commands/*.go ../utils/*.go ../broker.pb.go 
	@$(GO) build -o $(EXEC)

handlers:
	@(cd handlers && $(MAKE))

clean:
	@(cd handlers && $(MAKE) $@)
	@$(RM) $(EXEC) || true
	@$(RM) ./mocks/*.go || true
