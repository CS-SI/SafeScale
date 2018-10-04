GO?=go

.PHONY: generate clean

all: generate

vet:
	@$(GO) vet ./...

generate: dcos.go scripts/*.sh
	@$(GO) generate ./...

clean:
	@(cd enums && $(MAKE) $@)
	@($(RM) -f rice-box.go || true)

