GO?=go

.PHONY:	clean generate vet

DIRECTORIES := $(sort $(dir $(wildcard */)))

all: generate

generate:
	@(mkdir -p ./mocks) || true
	@(cd enums && $(MAKE) $(@))
	@(cd abstract && $(MAKE) $(@))
	@(cd operations && $(MAKE) $(@))

vet:
	@$(GO) vet ./...

test:
	@$(GO) test $(RACE_CHECK_TEST) $(GO_TEST_TAGS) -v ./...

clean:
	@$(RM) ./mocks/mock_*.go || true
	@(cd enums && $(MAKE) $(@))
	@(cd operations && $(MAKE) $(@))
