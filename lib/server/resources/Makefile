GO?=go

.PHONY:	clean generate vet

DIRECTORIES := $(sort $(dir $(wildcard */)))

all: generate

generate:
	@(cd enums && $(MAKE) $(@))
	@(cd operations && $(MAKE) $(@))

vet:
	@$(GO) vet ./...

test:
	@$(GO) test ./...

clean:
	@(cd enums && $(MAKE) $(@))
	@(cd operations && $(MAKE) $(@))
