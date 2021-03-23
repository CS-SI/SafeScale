GO?=go

.PHONY:	clean generate vet

DIRECTORIES := $(sort $(dir $(wildcard */)))

all: generate

generate:
	@(mkdir -p mocks) || true
	@(cd enums && $(MAKE) $(@))
	@(cd operations && $(MAKE) $(@))

vet:
	@$(GO) vet ./...

test:
	@$(GO) test $(RACE_CHECK_TEST) -v ./...

clean:
	@(cd enums && $(MAKE) $(@))
	@(cd operations && $(MAKE) $(@))
