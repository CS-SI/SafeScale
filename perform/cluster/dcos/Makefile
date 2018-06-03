GO?=go

all: generate vet

.PHONY: generate clean mrproper

vet:
	@$(GO) vet


generate: cluster.go scripts/*.sh
	@echo "Generating dependencies..."
	@$(GO) generate

clean:
	@($(RM) -f rice-box.go)

mrproper: clean

