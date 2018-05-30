all: components

.PHONY: components

components: prepare.go scripts/*
	@go generate

clean:
	@($(RM) rice-box.go)

