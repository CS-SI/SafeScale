GO?=go

.PHONY:	clean generate vet

all: generate

generate: clean
	@(mkdir -p mocks) || true
	@(mkdir -p providers/mocks) || true
	@(mkdir -p ../mocks) || true
	@(cd providers && $(MAKE) $(@))
	@(cd userdata && $(MAKE) $(@))
	@(cd stacks && $(MAKE) $(@))
	@$(GO) generate ./... > /dev/null 2>&1 || true

vet:
	@$(GO) vet ./...

clean:
	@(cd providers && $(MAKE) $(@))
	@(cd userdata && $(MAKE) $(@))
	@(cd stacks && $(MAKE) $(@))
	@$(RM) ./mocks/mock_*.go || true
