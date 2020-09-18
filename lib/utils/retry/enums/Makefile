GO?=go

.PHONY: all clean generate vet

all: generate

generate:
	@$(GO) generate -run stringer ./...

vet:
	@$(GO) vet $(BUILD_TAGS) ./...

clean:
	@$(RM) */enum_string.go || true
