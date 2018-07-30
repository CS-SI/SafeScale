GO?=go

.PHONY:	generate clean

all:	generate vet

vet:
	@$(GO) vet

generate:
	@$(GO) generate

clean:
	@($(RM) rice-box.go)
