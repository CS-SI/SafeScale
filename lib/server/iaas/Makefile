GO?=go

.PHONY:	clean generate vet

all: generate

generate: clean
	@(cd providers && $(MAKE) $(@))

vet:
	@$(GO) vet ./...

clean:
	@(cd providers && $(MAKE) $(@))
	@$(RM) ./mocks/*.go || true
