include ../common.mk

.PHONY:	cli/safescale cli/safescaled cli/perform cli/scanner clean vet

all:	cli/safescale cli/safescaled cli/perform cli/scanner

vet:
	@(cd safescale && $(MAKE) $@)
	@(cd safescaled && $(MAKE) $@)
	@(cd scanner && $(MAKE) $@)
	@(cd perform && $(MAKE) $@)

cli/safescale:
	@printf "%b" "$(MAKE_TRACE)$(OK_COLOR)$(INFO_STRING) Building binary safescale, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd safescale && $(MAKE))

cli/safescaled:
	@printf "%b" "$(MAKE_TRACE)$(OK_COLOR)$(INFO_STRING) Building binary safescaled, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd safescaled && $(MAKE))

cli/scanner:
	@printf "%b" "$(MAKE_TRACE)$(OK_COLOR)$(INFO_STRING) Building binary scanner, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd scanner && $(MAKE))

cli/perform:
	@printf "%b" "$(MAKE_TRACE)$(OK_COLOR)$(INFO_STRING) Building binary perform, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd perform && $(MAKE))

generate:
	@(cd perform && $(MAKE) $(@))

clean:
	@(cd safescale && $(MAKE) $(@))
	@(cd safescaled && $(MAKE) $(@))
	@(cd scanner && $(MAKE) $(@))
	@(cd perform && $(MAKE) $(@))
