
GO?=go

.PHONY: vet generate clean

all: generate

vet:
	@$(GO) vet ./...

generate: clean
	@$(GO) generate ./...

clean:
	@$(RM) */enum_string.go || true

