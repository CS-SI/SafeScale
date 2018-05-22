all: generate

.PHONY: clean mrproper

generate: cluster.go scripts/*
	@echo "Generating dependencies..."
	@go generate

clean:
	@(rm -f rice-box.go)

mrproper: clean

