all: components

.PHONY: components

components: prepare.go scripts/*
	@go generate

clean:
	@rm rice-box.go

