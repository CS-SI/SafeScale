GO?=go

.PHONY:	clean generate vet

DIRECTORIES := $(sort $(dir $(wildcard */)))

generate:
	@(cd enums && $(MAKE) $(@))
	@(cd userdata && $(MAKE) $(@))

vet:
	@$(GO) vet ./...

clean: 
	@(cd enums && $(MAKE) $(@))
	@(cd userdata && $(MAKE) $(@))
	@$(RM) rice-box.go enums/*/enum_string.go
