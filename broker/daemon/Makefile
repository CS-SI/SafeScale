GO?=go
EXEC:=brokerd

.PHONY:	brokerd services clean

vet:
	@$(GO) vet
	@$(GO) vet ./commands

all:	brokerd vet

brokerd: services main.go commands/*.go ../utils/*.go ../broker.pb.go 
	@$(GO) build -o $(EXEC)

services:
	@(cd services && $(MAKE))

clean:
	@(cd services && $(MAKE) $@)
	@$(RM) $(EXEC)
