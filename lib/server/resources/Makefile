GO?=go

.PHONY:	clean generate vet

DIRECTORIES := $(sort $(dir $(wildcard */)))

all: generate

generate:
	@(cd enums && $(MAKE) $(@))
	@(cd payloads && $(MAKE) $(@))

vet:
	@$(GO) vet ./...

clean: 
	@(cd enums && $(MAKE) $(@))
	@(cd payloads && $(MAKE) $(@))
	@$(RM) rice-box.go
