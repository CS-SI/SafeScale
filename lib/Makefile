include ../common.mk

.PHONY:	sdk client server utils system clean vet

# Handling multiple gopath: use $(HOME)/go by default
ifeq ($(findstring :,$(GOPATH)),:)
ifeq (, $(GOMODPATH))
$(error "Having a GOPATH with several directories is not recommended, when you have such a GOPATH: [$(GOPATH)], you must specify where your go modules are installed; by default the build looks for modules in 'GOMODPATH/pkg/mod' directory, so you must export the GOMODPATH variable before running the build")
endif
else
GOMODPATH?=$(GOPATH)
endif

ifeq ($(strip $(GOPATH)),)
GOMODPATH?=$(HOME)/go
endif

ifneq ($(OS),Windows_NT)
PATH = $(HOME)/.local/bin:$(shell printenv PATH)
endif

all:	sdk lib/system lib/utils lib/server lib/client

vet:
	@$(GO) vet ./...

gensrc:
	@(cd server/iaas/resources/userdata && $(MAKE) $(@))
	@(cd system && $(MAKE) $(@))

generate: gensrc sdk
	@(cd server/iaas/resources/enums && $(MAKE) $@)
	@(cd server && $(MAKE) $@)
	@(cd system && $(MAKE) $@)
	@(cd security && $(MAKE) $@)
	@(cd utils && $(MAKE) $@)

lib/client:
	@printf "%b" "$(MAKE_TRACE)$(OK_COLOR)$(INFO_STRING) Building library client, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd utils && $(MAKE) all)

lib/server:
	@printf "%b" "$(MAKE_TRACE)$(OK_COLOR)$(INFO_STRING) Building library server, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd server && $(MAKE) all)

lib/system:
	@printf "%b" "$(MAKE_TRACE)$(OK_COLOR)$(INFO_STRING) Building library system, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd system && $(MAKE) all)

lib/utils:
	@printf "%b" "$(MAKE_TRACE)$(OK_COLOR)$(INFO_STRING) Building library utils, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd utils && $(MAKE) all)

sdk:
	@printf "%b" "$(MAKE_TRACE)$(OK_COLOR)$(INFO_STRING) Building using $(GOMODPATH)/pkg/mod, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@ln -f -s $(GOMODPATH)/pkg/mod/github.com/golang/protobuf@v1.3.2 $(GOMODPATH)/pkg/mod/github.com/golang/protobuf 2> /dev/null || true
	@protoc -I. -I$(GOMODPATH)/pkg/mod --go_out=plugins=grpc:. safescale.proto

has_python:
	@which python3 > /dev/null; if [ $$? -ne 0 ]; then echo "No python installed !"; exit 1; fi
	@which pip3 > /dev/null; if [ $$? -ne 0 ]; then echo "No pip installed !"; exit 1; fi
	@which pipenv > /dev/null; if [ $$? -ne 0 ]; then echo "No pipenv installed !"; exit 1; fi

prepare_python:
	@which pip3 > /dev/null; if [ $$? -ne 0 ]; then echo "No pip installed !"; exit 1; fi
	@pip3 install --user pipenv

sdk_python: has_python sdk
	@mkdir -p ./python3
	@pipenv update
	@cp safescale.proto safescale.proto.backup
	@sed -i 's/github.com\/golang\/protobuf\/ptypes\/empty\/empty.proto/google\/protobuf\/empty.proto/g' safescale.proto
	@pipenv run python3 -m grpc_tools.protoc -I. -I$(GOMODPATH)/src -I$(GOMODPATH)/pkg/mod --python_out=python3/ --grpc_python_out=python3/ safescale.proto
	@mv safescale.proto.backup safescale.proto
	@protoc -I. -I$(GOMODPATH)/src -I$(GOMODPATH)/pkg/mod --go_out=plugins=grpc:. safescale.proto

force_sdk_python: prepare_python sdk_python

clean:
	@($(RM) safescale_pb2.py || true)
	@(cd server && $(MAKE) $@)
	@(cd system && $(MAKE) $@)
