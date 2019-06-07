GO?=go

.PHONY: all clean generate vet


all: generate

generate:
	@$(GO) generate -run rice

vet:
	@$(GO) vet ./...

clean:
	@($(RM) -f rice-box.go || true)

