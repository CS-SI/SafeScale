GO?=go

.PHONY:	brokerd commands clean

all:	brokerd

brokerd: commands main.go commands/*.go ../utils/*.go ../broker.pb.go
	@$(GO) build

commands:
	@(cd commands && $(MAKE))

clean:
	@(cd commands && $(MAKE) $@)
	@$(RM) brokerd
