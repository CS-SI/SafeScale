GO?=go

.PHONY:	broker clean

all:	broker

broker:	main.go cmd/*.go ../utils/*.go ../broker.pb.go
	@$(GO) build

clean:
	@$(RM) broker
