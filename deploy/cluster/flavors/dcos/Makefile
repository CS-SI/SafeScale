GO?=go

.PHONY: generate clean

all: generate

vet:
	@$(GO) vet ./...

generate: dcos.go scripts/*.sh
	@$(GO) generate ./...

clean:
	@($(RM) -f rice-box.go || true)
	@($(RM) ErrorCode/*_string.go || true)
