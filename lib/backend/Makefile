include ../../common.mk

.PHONY:	lib/backend/resources lib/backend/iaas clean vet

all:	lib/backend/iaas lib/backend/resources

minimock: generate

generate: clean
	@(mkdir -p mocks) || true
	@(cd iaas && $(MAKE) $@)
	@(cd resources && $(MAKE) $@)
	@(cd handlers && $(MAKE) $@)

vet:
	@$(GO) vet ./...

test:
	@$(GO) test $(RACE_CHECK_TEST) $(GO_TEST_TAGS) -timeout 900s -v ./... -p 1 $(TEST_COVERAGE_ARGS) 2>&1

lib/backend/iaas:
	@printf "%b" "$(MAKE_TRACE)$(OK_COLOR)$(INFO_STRING) Building component iaas, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd iaas && $(MAKE))

lib/backend/resources:
	@printf "%b" "$(MAKE_TRACE)$(OK_COLOR)$(INFO_STRING) Building component resources, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd resources && $(MAKE))

lib/backend/handlers:
	@printf "%b" "$(MAKE_TRACE)$(OK_COLOR)$(INFO_STRING) Building component handlers, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd handlers && $(MAKE))

clean:
	@(cd handlers && $(MAKE) $@)
	@(cd iaas && $(MAKE) $@)
	@(cd resources && $(MAKE) $@)
	@$(RM) ./mocks/mock_*.go || true
