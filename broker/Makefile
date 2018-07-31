GOPATH?=$(HOME)/go
GO?=go

.PHONY:	sdk broker brokerd clean

all:	brokerd broker

vet:
	@$(GO) vet
	@$(GO) vet ./utils

sdk:	broker.proto
	@protoc -I. -I$(GOPATH)/src --go_out=plugins=grpc:. broker.proto

brokerd:	sdk
	@(cd daemon && $(MAKE) $@)

broker:	sdk
	@(cd client && $(MAKE) $@)

clean:
	@(cd client && $(MAKE) $@)
	@(cd daemon && $(MAKE) $@)
	@($(RM) broker_pb2.py broker.pb.go)
