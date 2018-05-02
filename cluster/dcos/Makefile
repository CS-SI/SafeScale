all: generate

.PHONY: clean mrproper

generate: cluster.go
	@go generate


clean:
	@(rm -f rice-box.go)

mrproper: clean

