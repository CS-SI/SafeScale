GO?=go

.PHONY: components

all: components

vet:
	@$(GO) vet

components: prepare.go scripts/*
	@go generate

clean:
	@($(RM) rice-box.go)

