all:	brokerd

.PHONY:	commands clean

brokerd: main.go commands/*.go ../utils/*.go ../brokerd.pb.go
	@go build

commands:
	@(cd commands && $(MAKE) $@)

clean:
	@(cd commands && $(MAKE) $@)
	@rm -f brokerd
