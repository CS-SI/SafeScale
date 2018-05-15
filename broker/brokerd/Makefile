all:	brokerd

.PHONY:	brokerd commands clean

brokerd: commands main.go commands/*.go ../utils/*.go ../broker.pb.go
	@go build

commands:
	@(cd commands && $(MAKE))

clean:
	@(cd commands && $(MAKE) $@)
	@rm -f brokerd
