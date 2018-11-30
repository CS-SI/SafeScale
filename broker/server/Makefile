GO?=go
EXEC:=brokerd

.PHONY:	brokerd services clean

all:	brokerd 

vet:
	@$(GO) vet ./...

brokerd: services
	@$(GO) build -o $(EXEC)

services:
	@(cd services && $(MAKE))

clean:
	@(cd services && $(MAKE) $@)
	@$(RM) $(EXEC) || true
	@$(RM) ./mocks/*.go || true
