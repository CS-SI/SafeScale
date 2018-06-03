GOPATH?=$(HOME)/go
GO?=go


all:	brokerd broker vet

.PHONY:	sdk broker brokerd clean

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
