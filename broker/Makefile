GOINCLUDEPATH?=$(GOPATH)

GO?=go

.PHONY:	sdk clean vet

# Handling multiple gopath: use $(HOME)/go by default
ifeq ($(findstring :,$(GOINCLUDEPATH)),:)
    GOINCLUDEPATH=$(HOME)/go
else
	GOINCLUDEPATH=$(GOPATH)
endif

all:	cli

vet:
	@$(GO) vet ./...

sdk:
	@protoc -I. -I$(GOINCLUDEPATH)/src --go_out=plugins=grpc:. broker.proto

cli:	sdk
	@(cd cli && $(MAKE))

clean:
	@(cd cli && $(MAKE) $@)
	@($(RM) broker_pb2.py || true)
	@(cd server && $(MAKE) $@)
