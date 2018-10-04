GO?=go

.PHONY: generate clean mrproper

all: generate

vet:
	@$(GO) vet ./...

generate: k8s.go scripts/*.sh
	@$(GO) generate

clean:
	@($(RM) -f rice-box.go)

mrproper: clean
