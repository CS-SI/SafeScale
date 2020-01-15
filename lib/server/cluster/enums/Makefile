GO?=go

.PHONY: all clean generate vet

DIRECTORIES := $(sort $(dir $(wildcard */)))

generate: clean
	@$(GO) generate -run stringer ./...

vet:
	@$(GO) vet ./...

clean:
	@$(RM) */enum_string.go || true

