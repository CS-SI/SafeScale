include ../common.mk

.PHONY:	cli/safescale clean vet #cli/safescaled

all:	cli/safescale #cli/safescaled

vet:
	@(cd safescale && $(MAKE) $@)
	#@(cd safescaled && $(MAKE) $@)

beta:
	@$(eval GO = "go1.18beta1")

cli/safescale:
	@printf "%b" "$(MAKE_TRACE)$(OK_COLOR)$(INFO_STRING) Building binary safescale, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
	@(cd safescale && $(MAKE))

#cli/safescaled:
#	@printf "%b" "$(MAKE_TRACE)$(OK_COLOR)$(INFO_STRING) Building binary safescaled, $(NO_COLOR)target $(OBJ_COLOR)$(@)$(NO_COLOR)\n";
#	@(cd safescaled && $(MAKE))

generate:
	@(cd safescale && $(MAKE) $(@))
	#@(cd safescaled && $(MAKE) $(@))

gensrc:
	@(cd safescale && $(MAKE) $(@))
	#@(cd safescaled && $(MAKE) $(@))

clean:
	@(cd safescale && $(MAKE) $(@))
	#@(cd safescaled && $(MAKE) $(@))
