GOINCLUDEPATH?=$(GOPATH)

GO?=go

.PHONY:	sdk clean vet

# Handling multiple gopath: use $(HOME)/go by default
ifeq ($(findstring :,$(GOINCLUDEPATH)),:)
    GOINCLUDEPATH=$(HOME)/go
else
	GOINCLUDEPATH=$(GOPATH)
endif

all:	sdk

vet:
	@$(GO) vet ./...

sdk:
	@protoc -I. -I$(GOINCLUDEPATH)/src --go_out=plugins=grpc:. model.proto

clean:
	@($(RM) model_pb2.py || true)
