ndef = $(if $(value $(1)),,$(error $(1) not set))
.PHONY:	sdk clean vet

GO?=go

# Handling multiple gopath: use $(HOME)/go by default
ifeq ($(findstring :,$(GOPATH)),:)
	GOINCLUDEPATH=$(HOME)/go
else
	GOINCLUDEPATH=$(GOPATH)
endif

ifeq ($(strip $(ǴOPATH)),)
	GOINCLUDEPATH=$(HOME)/go
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
