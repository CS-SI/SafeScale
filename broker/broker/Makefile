all:	broker

.PHONY:	clean

broker:	main.go cmd/*.go ../utils/*.go ../brokerd.pb.go
	go build

clean:
	@rm -f broker
