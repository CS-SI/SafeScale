GO?=go
all: components vet

.PHONY: components


vet:
	@$(GO) vet


components: prepare.go scripts/*
	@go generate

clean:
	@($(RM) rice-box.go)

