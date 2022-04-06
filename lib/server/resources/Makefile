GO?=go

.PHONY:	clean generate vet

DIRECTORIES := $(sort $(dir $(wildcard */)))

all: generate

generate:
	@(mkdir -p ./mocks) || true
	@$(GO) generate -run minimock . >/dev/null || true
	@(cd enums && $(MAKE) $(@))
	@(cd operations && $(MAKE) $(@))

vet:
	@$(GO) vet ./...

test:
	@$(GO) test $(RACE_CHECK_TEST) $(GO_TEST_TAGS) -v ./...

clean:
	@$(RM) ./mocks/*.go || true
	@(cd enums && $(MAKE) $(@))
	@(cd operations && $(MAKE) $(@))
