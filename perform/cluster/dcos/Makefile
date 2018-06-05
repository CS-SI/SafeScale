GO?=go

all: generate

.PHONY: generate clean mrproper

generate: dcos.go scripts/*.sh
	@echo "Generating dependencies..."
	@$(GO) generate

clean:
	@($(RM) -f rice-box.go)

mrproper: clean

