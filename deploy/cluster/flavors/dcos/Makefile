GO?=go

.PHONY: generate clean mrproper

all: generate

vet:
	@$(GO) vet
	@$(GO) vet ./ErrorCode

generate: dcos.go scripts/*.sh
	@$(GO) generate

clean:
	@($(RM) -f rice-box.go)

mrproper: clean
