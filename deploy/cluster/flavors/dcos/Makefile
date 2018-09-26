GO?=go

.PHONY: generate clean mrproper

all: generate

vet:
	@$(GO) vet ./...

generate: dcos.go scripts/*.sh
	@$(GO) generate

clean:
	@($(RM) -f rice-box.go)
	@($(RM) ErrorCode/*_string.go)

mrproper: clean
