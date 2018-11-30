.PHONY:	sdk clean vet

GO?=go

# Handling multiple gopath: use $(HOME)/go by default
ifeq ($(findstring :,$(GOPATH)),:)
	GOINCLUDEPATH=$(HOME)/go
else
	GOINCLUDEPATH=$(GOPATH)
endif

ifeq ($(strip $(GOPATH)),)
	GOINCLUDEPATH=$(HOME)/go
endif

all:	cli

vet:
	@$(GO) vet ./...

sdk:
	@protoc -I. -I$(GOINCLUDEPATH)/src --go_out=plugins=grpc:. broker.proto

has_python:
	@which python3 > /dev/null; if [ $$? -ne 0 ]; then echo "No python installed !"; exit 1; fi
	@which pip > /dev/null; if [ $$? -ne 0 ]; then echo "No pip installed !"; exit 1; fi
	@which pipenv > /dev/null; if [ $$? -ne 0 ]; then echo "No pipenv installed !"; exit 1; fi

prepare_python:
	@which pip > /dev/null; if [ $$? -ne 0 ]; then echo "No pip installed !"; exit 1; fi
	@pip install --user pipenv

sdk_python: has_python sdk
	@mkdir -p ./python3
	@~/.local/bin/pipenv update
	@cp broker.proto broker.proto.backup
	@sed -i 's/github.com\/golang\/protobuf\/ptypes\/empty\/empty.proto/google\/protobuf\/empty.proto/g' broker.proto
	@~/.local/bin/pipenv run python3 -m grpc_tools.protoc -I. -I$(GOINCLUDEPATH)/src --python_out=python3/ --grpc_python_out=python3/ broker.proto
	@mv broker.proto.backup broker.proto
	@protoc -I. -I$(GOINCLUDEPATH)/src --go_out=plugins=grpc:. broker.proto

force_sdk_python: prepare_python sdk_python

cli:	sdk
	@(cd cli && $(MAKE))

clean:
	@(cd cli && $(MAKE) $@)
	@($(RM) broker_pb2.py || true)
	@(cd server && $(MAKE) $@)
