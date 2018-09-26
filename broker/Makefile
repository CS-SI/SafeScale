GOPATH?=$(HOME)/go
GO?=go

.PHONY:	sdk clean

all:	cli

vet:
	@$(GO) vet ./...

sdk:	broker.proto
	@[ ! -f ./broker.pb.go ] && protoc -I. -I$(GOPATH)/src --go_out=plugins=grpc:. broker.proto || true

cli:	sdk
	@(cd cli && $(MAKE))

clean:
	@(cd cli && $(MAKE) $@)
	@($(RM) broker_pb2.py)
