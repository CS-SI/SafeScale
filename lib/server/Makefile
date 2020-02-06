include ../../common.mk

.PHONY:	lib/server/resources lib/server/handlers lib/server/iaas clean vet

all:	lib/server/iaas lib/server/resources lib/server/handlers

generate: clean
	@(cd iaas && $(MAKE) $@)
	@(cd resources && $(MAKE) $@)
	@(cd iaas && $(MAKE) $@)

vet:
	@$(GO) vet ./...

lib/server/iaas:
	@printf "%b" "$(MAKE_TRACE)$(OK_COLOR)$(INFO_STRING) Building component iaas, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd iaas && $(MAKE))

lib/server/resources:
	@printf "%b" "$(MAKE_TRACE)$(OK_COLOR)$(INFO_STRING) Building component resources, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd resources && $(MAKE))

lib/server/handlers:
	@printf "%b" "$(MAKE_TRACE)$(OK_COLOR)$(INFO_STRING) Building component handlers, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd handlers && $(MAKE))

clean:
	@(cd iaas && $(MAKE) $@)
	@(cd handlers && $(MAKE) $@)
	@(cd resources && $(MAKE) $@)
	@$(RM) ./mocks/*.go || true
