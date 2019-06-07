include ../../common.mk

.PHONY:	lib/server/cluster lib/server/handlers lib/server/iaas lib/server/install clean vet

all:	lib/server/iaas lib/server/cluster lib/server/handlers lib/server/install

generate:
	@(cd iaas && $(MAKE) $@)
	@(cd cluster && $(MAKE) $@)
	@(cd install && $(MAKE) $@)

vet:
	@$(GO) vet ./...

lib/server/iaas:
	@printf "%b" "$(MAKE_TRACE)$(OK_COLOR)$(INFO_STRING) Building component iaas, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd iaas && $(MAKE))

lib/server/cluster:
	@printf "%b" "$(MAKE_TRACE)$(OK_COLOR)$(INFO_STRING) Building component cluster, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd cluster && $(MAKE))

lib/server/handlers:
	@printf "%b" "$(MAKE_TRACE)$(OK_COLOR)$(INFO_STRING) Building component handlers, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd handlers && $(MAKE))

lib/server/install:
	@printf "%b" "$(MAKE_TRACE)$(OK_COLOR)$(INFO_STRING) Building component install, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd install && $(MAKE))

clean:
	@(cd iaas && $(MAKE) $@)
	@(cd handlers && $(MAKE) $@)
	@(cd cluster && $(MAKE) $@)
	@(cd install && $(MAKE) $@)
	@$(RM) ./mocks/*.go || true
