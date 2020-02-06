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

all:	sdk lib/protocol lib/system lib/utils lib/server lib/client

vet:
	@$(GO) vet ./...

generate: sdk
	@(cd protocol && $(MAKE) $@)
	@(cd server && $(MAKE) $@)
	@(cd system && $(MAKE) $@)
	@(cd utils && $(MAKE) $@)

lib/protocol:
	@printf "%b" "$(MAKE_TRACE)$(OK_COLOR)$(INFO_STRING) Building protocol, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd protocol && $(MAKE) all)

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

clean:
	@(cd protocol && $(MAKE) clean)
	@(cd server && $(MAKE) clean)
	@(cd system && $(MAKE) clean)
	@(cd utils && $(MAKE) clean)
